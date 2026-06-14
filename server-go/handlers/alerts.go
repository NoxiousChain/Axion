package handlers

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/axion/server/middleware"
	"github.com/axion/server/models"
	"github.com/gin-gonic/gin"
)

// IngestAlert — POST /api/alerts
func (h *Handler) IngestAlert(c *gin.Context) {
	var payload models.AlertPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"detail": err.Error()})
		return
	}
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	if payload.Ts == 0 {
		payload.Ts = float64(time.Now().UnixMicro()) / 1e6
	}
	if payload.Details == nil {
		payload.Details = []byte("{}")
	}

	var alertID int64
	err := h.db.Pool.QueryRow(ctx,
		`INSERT INTO alerts (ts, detector, severity, title, details, node_id, location)
		 VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
		payload.Ts, payload.Detector, payload.Severity, payload.Title,
		payload.Details, payload.NodeID, payload.Location,
	).Scan(&alertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}

	// Correlate into an incident (simple entity-based grouping, 5-min window)
	incidentID := h.correlate(ctx, alertID, &payload)

	// Broadcast over WebSocket
	h.hub.Broadcast(gin.H{
		"type":        "alert",
		"id":          alertID,
		"detector":    payload.Detector,
		"severity":    payload.Severity,
		"title":       payload.Title,
		"ts":          payload.Ts,
		"node_id":     payload.NodeID,
		"incident_id": incidentID,
	})

	h.db.Audit(ctx, fmt.Sprint(actor), "alert_ingested",
		fmt.Sprintf("alert:%d", alertID), payload.Severity)

	c.JSON(http.StatusCreated, gin.H{"alert_id": alertID, "incident_id": incidentID})
}

// ListAlerts — GET /api/alerts
func (h *Handler) ListAlerts(c *gin.Context) {
	ctx := c.Request.Context()
	limit := 100
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "100")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(c.DefaultQuery("offset", "0")); err == nil {
		offset = o
	}

	q := `SELECT id, ts, detector, severity, title, details, node_id, location,
	             acked, acked_by, acked_at, incident_id
	      FROM alerts WHERE 1=1`
	args := []any{}
	argN := 1

	if sev := c.Query("severity"); sev != "" {
		q += fmt.Sprintf(" AND severity = $%d", argN)
		args = append(args, sev)
		argN++
	}
	if det := c.Query("detector"); det != "" {
		q += fmt.Sprintf(" AND detector = $%d", argN)
		args = append(args, det)
		argN++
	}
	if node := c.Query("node_id"); node != "" {
		q += fmt.Sprintf(" AND node_id = $%d", argN)
		args = append(args, node)
		argN++
	}
	if search := c.Query("q"); search != "" {
		pattern := "%" + search + "%"
		q += fmt.Sprintf(
			" AND (title ILIKE $%d OR details::text ILIKE $%d OR node_id ILIKE $%d OR detector ILIKE $%d OR location ILIKE $%d)",
			argN, argN, argN, argN, argN,
		)
		args = append(args, pattern)
		argN++
	}
	if c.Query("hide_acked") == "true" {
		q += " AND acked = FALSE"
	}

	q += fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d OFFSET $%d", argN, argN+1)
	args = append(args, limit, offset)

	rows, err := h.db.Pool.Query(ctx, q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	defer rows.Close()

	var alerts []models.Alert
	for rows.Next() {
		var a models.Alert
		rows.Scan(&a.ID, &a.Ts, &a.Detector, &a.Severity, &a.Title,
			&a.Details, &a.NodeID, &a.Location,
			&a.Acked, &a.AckedBy, &a.AckedAt, &a.IncidentID)
		alerts = append(alerts, a)
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	c.JSON(http.StatusOK, alerts)
}

// AckAlert — POST /api/alerts/:id/ack
func (h *Handler) AckAlert(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var body models.AckBody
	c.ShouldBindJSON(&body)
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	ts := float64(time.Now().UnixMicro()) / 1e6
	ct, err := h.db.Pool.Exec(ctx,
		`UPDATE alerts SET acked = TRUE, acked_by = $1, acked_at = $2 WHERE id = $3`,
		body.By, ts, id,
	)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "alert not found"})
		return
	}

	h.db.Audit(ctx, fmt.Sprint(actor), "ack_alert", fmt.Sprintf("alert:%d", id), body.Note)
	c.JSON(http.StatusOK, gin.H{"detail": "acknowledged"})
}

// Stats — GET /api/stats?window_minutes=N  (0 or omitted = all time)
func (h *Handler) Stats(c *gin.Context) {
	ctx := c.Request.Context()

	windowMins, _ := strconv.Atoi(c.DefaultQuery("window_minutes", "0"))

	var timeFilter string
	var timeArgs []any
	if windowMins > 0 {
		cutoff := float64(time.Now().Add(-time.Duration(windowMins)*time.Minute).UnixMicro()) / 1e6
		timeFilter = " WHERE ts >= $1"
		timeArgs = []any{cutoff}
	}

	bySeverity := map[string]int{}
	if rows, err := h.db.Pool.Query(ctx,
		"SELECT severity, COUNT(*) FROM alerts"+timeFilter+" GROUP BY severity",
		timeArgs...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			rows.Scan(&sev, &cnt)
			bySeverity[sev] = cnt
		}
	}

	byDetector := map[string]int{}
	if rows, err := h.db.Pool.Query(ctx,
		"SELECT detector, COUNT(*) FROM alerts"+timeFilter+
			" GROUP BY detector ORDER BY COUNT(*) DESC LIMIT 10",
		timeArgs...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var det string
			var cnt int
			rows.Scan(&det, &cnt)
			byDetector[det] = cnt
		}
	}

	byNode := map[string]int{}
	if rows, err := h.db.Pool.Query(ctx,
		"SELECT node_id, COUNT(*) FROM alerts"+timeFilter+
			" GROUP BY node_id ORDER BY COUNT(*) DESC LIMIT 20",
		timeArgs...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var node string
			var cnt int
			rows.Scan(&node, &cnt)
			if node != "" {
				byNode[node] = cnt
			}
		}
	}

	// Timeline: hourly buckets over the requested window (default: last 24 h).
	tlFilter, tlArgs := timeFilter, timeArgs
	if windowMins == 0 {
		cutoff24h := float64(time.Now().Add(-24*time.Hour).UnixMicro()) / 1e6
		tlFilter = " WHERE ts >= $1"
		tlArgs = []any{cutoff24h}
	}
	timeline := []map[string]any{}
	if rows, err := h.db.Pool.Query(ctx,
		"SELECT date_trunc('hour', to_timestamp(ts)) AS hr, COUNT(*) FROM alerts"+
			tlFilter+" GROUP BY hr ORDER BY hr",
		tlArgs...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var hr time.Time
			var cnt int
			rows.Scan(&hr, &cnt)
			timeline = append(timeline, map[string]any{"ts": hr.Unix(), "count": cnt})
		}
	}

	var totalAlerts, openIncidents int
	h.db.Pool.QueryRow(ctx, "SELECT COUNT(*) FROM alerts"+timeFilter, timeArgs...).Scan(&totalAlerts)
	h.db.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM incidents WHERE status = 'open'`).Scan(&openIncidents)

	c.JSON(http.StatusOK, gin.H{
		"total_alerts":   totalAlerts,
		"open_incidents": openIncidents,
		"by_severity":    bySeverity,
		"by_detector":    byDetector,
		"by_node":        byNode,
		"timeline":       timeline,
	})
}
