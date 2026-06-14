package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/axion/server/middleware"
	"github.com/axion/server/models"
	"github.com/gin-gonic/gin"
)

// ListIncidents — GET /api/incidents
func (h *Handler) ListIncidents(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.db.Pool.Query(ctx,
		`SELECT i.id, i.ts, i.entity_type, i.entity_value, i.status,
		        i.severity, i.title, i.acked,
		        COUNT(a.id) AS alert_count
		 FROM incidents i
		 LEFT JOIN alerts a ON a.incident_id = i.id
		 GROUP BY i.id
		 ORDER BY i.ts DESC
		 LIMIT 200`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	defer rows.Close()

	var incidents []models.Incident
	for rows.Next() {
		var inc models.Incident
		rows.Scan(&inc.ID, &inc.Ts, &inc.EntityType, &inc.EntityValue,
			&inc.Status, &inc.Severity, &inc.Title, &inc.Acked, &inc.AlertCount)
		incidents = append(incidents, inc)
	}
	if incidents == nil {
		incidents = []models.Incident{}
	}
	c.JSON(http.StatusOK, incidents)
}

// GetIncident — GET /api/incidents/:id
func (h *Handler) GetIncident(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	ctx := c.Request.Context()

	var inc models.Incident
	err := h.db.Pool.QueryRow(ctx,
		`SELECT id, ts, entity_type, entity_value, status, severity, title, acked
		 FROM incidents WHERE id = $1`, id,
	).Scan(&inc.ID, &inc.Ts, &inc.EntityType, &inc.EntityValue,
		&inc.Status, &inc.Severity, &inc.Title, &inc.Acked)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"detail": "incident not found"})
		return
	}

	rows, _ := h.db.Pool.Query(ctx,
		`SELECT id, ts, detector, severity, title, details, node_id, location,
		        acked, acked_by, acked_at, incident_id
		 FROM alerts WHERE incident_id = $1 ORDER BY ts DESC`, id)
	var alerts []models.Alert
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var a models.Alert
			rows.Scan(&a.ID, &a.Ts, &a.Detector, &a.Severity, &a.Title,
				&a.Details, &a.NodeID, &a.Location,
				&a.Acked, &a.AckedBy, &a.AckedAt, &a.IncidentID)
			alerts = append(alerts, a)
		}
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}

	c.JSON(http.StatusOK, gin.H{"incident": inc, "alerts": alerts})
}

// AckIncident — POST /api/incidents/:id/ack  (bulk-acks all member alerts)
func (h *Handler) AckIncident(c *gin.Context) {
	id, _ := strconv.ParseInt(c.Param("id"), 10, 64)
	var body models.AckBody
	c.ShouldBindJSON(&body)
	actor, _ := c.Get(middleware.CtxActor)
	ctx := c.Request.Context()

	ts := float64(time.Now().UnixMicro()) / 1e6

	ct, err := h.db.Pool.Exec(ctx,
		`UPDATE incidents SET acked = TRUE WHERE id = $1`, id)
	if err != nil || ct.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"detail": "incident not found"})
		return
	}
	h.db.Pool.Exec(ctx,
		`UPDATE alerts SET acked = TRUE, acked_by = $1, acked_at = $2
		 WHERE incident_id = $3`,
		body.By, ts, id,
	)

	h.db.Audit(ctx, fmt.Sprint(actor), "ack_incident",
		fmt.Sprintf("incident:%d", id), body.Note)
	c.JSON(http.StatusOK, gin.H{"detail": "acknowledged"})
}

// correlate groups an incoming alert into an existing or new incident.
// Mirrors the Python correlator: same entity within 5-minute window → same incident.
func (h *Handler) correlate(ctx context.Context, alertID int64, p *models.AlertPayload) *int64 {
	entityType, entity := extractEntity(p)
	if entity == "" {
		return nil
	}

	windowStart := p.Ts - 300 // 5-minute window

	var incidentID int64
	err := h.db.Pool.QueryRow(ctx,
		`SELECT id FROM incidents
		 WHERE entity_value = $1 AND ts >= $2 AND status = 'open'
		 ORDER BY ts DESC LIMIT 1`,
		entity, windowStart,
	).Scan(&incidentID)

	if err != nil {
		// Create a new incident
		h.db.Pool.QueryRow(ctx,
			`INSERT INTO incidents (ts, entity_type, entity_value, status, severity, title)
			 VALUES ($1, $2, $3, 'open', $4, $5) RETURNING id`,
			p.Ts, entityType, entity, p.Severity,
			fmt.Sprintf("Incident: %s activity on %s", p.Detector, entity),
		).Scan(&incidentID)

		h.db.Audit(ctx, "__correlator__", "incident_correlated",
			fmt.Sprintf("incident:%d", incidentID), entity)
	}

	// Link alert → incident
	h.db.Pool.Exec(ctx,
		`UPDATE alerts SET incident_id = $1 WHERE id = $2`, incidentID, alertID)

	return &incidentID
}

// extractEntity returns the (type, value) of the most specific entity in the alert.
// Priority: dst_ip → src_ip → device_id → user → host → node_id → detector name.
func extractEntity(p *models.AlertPayload) (entityType, entityValue string) {
	if len(p.Details) > 0 {
		var d map[string]interface{}
		if jsonErr := json.Unmarshal(p.Details, &d); jsonErr == nil {
			for _, key := range []string{"dst_ip", "src_ip", "device_id", "user", "host"} {
				if v, ok := d[key].(string); ok && v != "" {
					return key, v
				}
			}
		}
	}
	if p.NodeID != "" {
		return "node_id", p.NodeID
	}
	return "detector", p.Detector
}
