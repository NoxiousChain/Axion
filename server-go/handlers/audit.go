package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"

	"github.com/axion/server/models"
	"github.com/gin-gonic/gin"
)

// ListAudit — GET /api/audit?limit=100&offset=0&action=login_success
func (h *Handler) ListAudit(c *gin.Context) {
	ctx := c.Request.Context()
	limit := 100
	if l, err := strconv.Atoi(c.DefaultQuery("limit", "100")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(c.DefaultQuery("offset", "0")); err == nil {
		offset = o
	}

	q := `SELECT id, ts, actor, action, target, detail, row_hmac FROM audit_log WHERE 1=1`
	args := []any{}
	argN := 1

	if action := c.Query("action"); action != "" {
		q += fmt.Sprintf(" AND action = $%d", argN)
		args = append(args, action)
		argN++
	}
	if actor := c.Query("actor"); actor != "" {
		q += fmt.Sprintf(" AND actor = $%d", argN)
		args = append(args, actor)
		argN++
	}

	q += fmt.Sprintf(" ORDER BY ts DESC LIMIT $%d OFFSET $%d", argN, argN+1)
	args = append(args, limit, offset)

	rows, err := h.db.Pool.Query(ctx, q, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	defer rows.Close()

	var entries []models.AuditEntry
	for rows.Next() {
		var e models.AuditEntry
		rows.Scan(&e.ID, &e.Ts, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.HMAC)
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []models.AuditEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"total": len(entries), "entries": entries})
}

// VerifyAudit — GET /api/audit/verify  (checks HMAC integrity of every row)
func (h *Handler) VerifyAudit(c *gin.Context) {
	ctx := c.Request.Context()
	rows, err := h.db.Pool.Query(ctx,
		`SELECT id, ts, actor, action, target, detail, row_hmac FROM audit_log ORDER BY id`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"detail": err.Error()})
		return
	}
	defer rows.Close()

	keyMaterial := sha256.Sum256([]byte("axion-audit-v1:" + h.getKey()))
	var total, ok int
	var tamperedIDs, missingHMACIDs []int64

	for rows.Next() {
		var e models.AuditEntry
		rows.Scan(&e.ID, &e.Ts, &e.Actor, &e.Action, &e.Target, &e.Detail, &e.HMAC)
		total++

		if e.HMAC == "" {
			missingHMACIDs = append(missingHMACIDs, e.ID)
			continue
		}

		msg := fmt.Sprintf("%f|%s|%s|%s|%s", e.Ts, e.Actor, e.Action, e.Target, e.Detail)
		mac := hmac.New(sha256.New, keyMaterial[:])
		mac.Write([]byte(msg))
		expected := hex.EncodeToString(mac.Sum(nil))

		if expected == e.HMAC {
			ok++
		} else {
			tamperedIDs = append(tamperedIDs, e.ID)
		}
	}

	integrity := "PASS"
	if len(tamperedIDs) > 0 || len(missingHMACIDs) > 0 {
		integrity = "FAIL"
	}
	if missingHMACIDs == nil {
		missingHMACIDs = []int64{}
	}
	if tamperedIDs == nil {
		tamperedIDs = []int64{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":            total,
		"ok":               ok,
		"tampered_ids":     tamperedIDs,
		"missing_hmac_ids": missingHMACIDs,
		"integrity":        integrity,
	})
}
