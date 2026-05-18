package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/funinthecloud/protosource"

	"github.com/funinthecloud/protosource-auth/app"
	rolev1 "github.com/funinthecloud/protosource-auth/gen/auth/role/v1"
	userv1 "github.com/funinthecloud/protosource-auth/gen/auth/user/v1"
)

// roleDiagnostic is the per-role report emitted by diagnose-user.
type roleDiagnostic struct {
	RoleID        string   `json:"role_id"`
	GrantRoleID   string   `json:"grant_role_id,omitempty"`
	Found         bool     `json:"found"`
	LoadError     string   `json:"load_error,omitempty"`
	State         string   `json:"state,omitempty"`
	FunctionCount int      `json:"function_count"`
	Functions     []string `json:"functions,omitempty"`
}

// userDiagnostic is the top-level JSON report.
type userDiagnostic struct {
	Backend          string           `json:"backend"`
	AggregatesTable  string           `json:"aggregates_table,omitempty"`
	EventsTable      string           `json:"events_table,omitempty"`
	UserID           string           `json:"user_id"`
	UserFound        bool             `json:"user_found"`
	UserLoadError    string           `json:"user_load_error,omitempty"`
	Email            string           `json:"email,omitempty"`
	UserState        string           `json:"user_state,omitempty"`
	RoleCount        int              `json:"role_count"`
	Roles            []roleDiagnostic `json:"roles"`
	GrantedCount     int              `json:"granted_count"`
	GrantedFunctions []string         `json:"granted_functions"`
}

// runDiagnoseUser prints the chain User → Roles → FunctionGrants the way
// service.Checker.resolveFunctions walks it, against the same backend the
// running service uses. Output is JSON on stdout.
//
// Flags:
//
//	--user-id <id>     The User aggregate id to load.
//	--email <addr>     Look up the user by email via the configured UserDirectory.
//
// Exactly one of --user-id / --email is required.
func runDiagnoseUser(ctx context.Context, args []string) error {
	flags := parseFlags(args)
	userID := flags.get("user-id")
	email := flags.get("email")
	if (userID == "") == (email == "") {
		return errors.New("diagnose-user requires exactly one of --user-id or --email")
	}

	cfg, err := loadConfigForMgr()
	if err != nil {
		return err
	}

	bundle, err := app.NewBundle(ctx, cfg)
	if err != nil {
		return fmt.Errorf("build bundle: %w", err)
	}
	defer func() { _ = bundle.Close() }()

	if email != "" {
		userID, err = bundle.Directory.FindByEmail(ctx, email)
		if err != nil {
			return fmt.Errorf("directory lookup for %q: %w", email, err)
		}
	}

	report := userDiagnostic{
		Backend:         string(cfg.Backend),
		AggregatesTable: cfg.AggregatesTable,
		EventsTable:     cfg.EventsTable,
		UserID:          userID,
		Email:           email,
	}

	userAgg, err := bundle.UserRepo.Load(ctx, userID)
	if err != nil {
		if errors.Is(err, protosource.ErrAggregateNotFound) {
			report.UserLoadError = "aggregate not found"
		} else {
			report.UserLoadError = err.Error()
		}
		return emitReport(report)
	}
	user, ok := userAgg.(*userv1.User)
	if !ok {
		report.UserLoadError = fmt.Sprintf("loaded user is %T, want *userv1.User", userAgg)
		return emitReport(report)
	}
	report.UserFound = true
	if report.Email == "" {
		report.Email = user.GetEmail()
	}
	report.UserState = user.GetState().String()

	grants := user.GetRoles()
	report.RoleCount = len(grants)

	roleIDs := make([]string, 0, len(grants))
	for k := range grants {
		roleIDs = append(roleIDs, k)
	}
	sort.Strings(roleIDs)

	seen := make(map[string]struct{})
	for _, roleID := range roleIDs {
		entry := roleDiagnostic{RoleID: roleID}
		if grant := grants[roleID]; grant != nil {
			entry.GrantRoleID = grant.GetRoleId()
		}

		roleAgg, err := bundle.RoleRepo.Load(ctx, roleID)
		switch {
		case errors.Is(err, protosource.ErrAggregateNotFound):
			entry.LoadError = "aggregate not found"
		case err != nil:
			entry.LoadError = err.Error()
		default:
			role, ok := roleAgg.(*rolev1.Role)
			if !ok {
				entry.LoadError = fmt.Sprintf("loaded role is %T, want *rolev1.Role", roleAgg)
				break
			}
			entry.Found = true
			entry.State = role.GetState().String()
			fns := make([]string, 0, len(role.GetFunctions()))
			for fn := range role.GetFunctions() {
				fns = append(fns, fn)
				if _, dup := seen[fn]; !dup && role.GetState() == rolev1.State_STATE_ACTIVE {
					seen[fn] = struct{}{}
					report.GrantedFunctions = append(report.GrantedFunctions, fn)
				}
			}
			sort.Strings(fns)
			entry.Functions = fns
			entry.FunctionCount = len(fns)
		}
		report.Roles = append(report.Roles, entry)
	}

	sort.Strings(report.GrantedFunctions)
	report.GrantedCount = len(report.GrantedFunctions)

	return emitReport(report)
}

func emitReport(r userDiagnostic) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}
