package httpapi

import (
	"net/http"
	"net/url"
	"strings"
)

type upstream uint8

const (
	authUpstream upstream = iota
	gameUpstream
	coreUpstream
	profileUpstream
	chatUpstream
)

type accessPolicy uint8

const (
	publicAccess accessPolicy = iota
	authenticatedAccess
	roleAccess
)

type routeSpec struct {
	method         string
	pattern        string
	upstream       upstream
	access         accessPolicy
	identityHeader string
}

type routeMatch struct {
	spec   routeSpec
	userID string
}

var apiRoutes = [...]routeSpec{
	{http.MethodPost, "/api/v1/auth/login", authUpstream, publicAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/auth/logout", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/auth/refresh", authUpstream, publicAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/ban", authUpstream, roleAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/ban", authUpstream, roleAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/session", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/session", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/session/all", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/user", authUpstream, publicAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/user", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPut, "/api/v1/user/email", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPut, "/api/v1/user/password", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPut, "/api/v1/user/role", authUpstream, roleAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/verification/email", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/verification/password-reset", authUpstream, publicAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/verification/send-email-verification-code", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/verification/send-password-reset-code", authUpstream, publicAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/ban/{email}", authUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/friend", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/friend/request", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/friend/request", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/friend/request/accept", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/friend/request/decline", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/user", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPut, "/api/v1/user", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/user/me", profileUpstream, authenticatedAccess, "userId"},
	{http.MethodGet, "/api/v1/friend/request/incoming/{userToGetFriendRequests}", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/friend/request/outgoing/{userToGetFriendRequests}", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/friend/{userToGetFriends}", profileUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/requests", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/sports", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/requests/users/{userId}", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/requests/{id}", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPut, "/api/v1/requests/{id}", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/cancel", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/join", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/leave", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/registration/close", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/registration/open", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/start", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/requests/{requestId}/join-requests", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{id}/kick/{targetUserId}", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/requests/{requestId}/join-requests/{participantId}/decision", coreUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/rank-tiers", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/results", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/voting", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/{userId}", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/{userId}/best-sport", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/{userId}/last-game", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/{userId}/other-sports", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/results/by-request/{activityRequestId}", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/voting/{activityRequestId}", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/{userId}/sports/{sportId}", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/leaderboards/{sportId}/{page}/{cntPerPage}", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/{userId}/matches/{page}/{cntPerPage}", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/message/activity-request", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/message/chat", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/message/private", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/report", chatUpstream, roleAccess, "X-User-Id"},
	{http.MethodPost, "/api/v1/report", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/report/all", chatUpstream, roleAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/message/activity-request/{activityRequestId}", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/message/chat/{chatId}", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/message/private/{recipientId}", chatUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodDelete, "/api/v1/report/{userId}", chatUpstream, roleAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/report/{userId}", chatUpstream, roleAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players", gameUpstream, authenticatedAccess, "X-User-Id"},
	{http.MethodGet, "/api/v1/players/", gameUpstream, authenticatedAccess, "X-User-Id"},
}

func findAPIRoute(method, escapedPath string) (routeMatch, bool) {
	for _, spec := range apiRoutes {
		userID, ok := matchPattern(spec.pattern, escapedPath)
		if ok && (method == "" || method == spec.method) {
			return routeMatch{
				spec:   spec,
				userID: userID,
			}, true
		}
	}

	return routeMatch{}, false
}

func allowedMethods(escapedPath string) string {
	var methods []string
	for _, spec := range apiRoutes {
		if _, ok := matchPattern(spec.pattern, escapedPath); ok {
			methods = append(methods, spec.method)
		}
	}
	return strings.Join(methods, ", ")
}

func matchPattern(pattern, escapedPath string) (userID string, ok bool) {
	if !strings.HasPrefix(pattern, "/") ||
		!strings.HasPrefix(escapedPath, "/") {
		return "", false
	}

	want := strings.Split(pattern[1:], "/")
	got := strings.Split(escapedPath[1:], "/")
	if len(want) != len(got) {
		return "", false
	}

	for i, segment := range want {
		value := got[i]

		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			decoded, valid := validPathParameter(value)
			if !valid {
				return "", false
			}

			if segment == "{userId}" {
				userID = decoded
			}

			continue
		}

		if value != segment {
			return "", false
		}
	}

	return userID, true
}

func validPathParameter(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	decoded, err := url.PathUnescape(value)
	if err != nil || decoded == "" || strings.Contains(decoded, "/") || decoded == "." || decoded == ".." {
		return "", false
	}
	return decoded, true
}
