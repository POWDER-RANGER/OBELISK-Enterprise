;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Defense Domain: STIG Automation
;; Maps to: DISA STIGs, NIST 800-53, DoD CMMC, SCAP
;; Purpose: Automated Security Technical Implementation Guides compliance
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain stig-automation)
  (:requirements :strips :typing :conditional-effects)

  (:types
    system - object
    stig-rule - object
    control - object
    finding - object
    remediation - object
    benchmark - object
    scan-profile - object
    technology - object
  )

  (:types
    operating-system - technology
    application - technology
    network-device - technology
    container-platform - technology
    database - technology
    web-server - technology
  )

  (:predicates
    ;; STIG categories (severity)
    (cat-i ?r - stig-rule)
    (cat-ii ?r - stig-rule)
    (cat-iii ?r - stig-rule)

    ;; STIG families
    (account-management ?r - stig-rule)
    (audit-and-accountability ?r - stig-rule)
    (boundary-protection ?r - stig-rule)
    (password-policy ?r - stig-rule)
    (session-management ?r - stig-rule)
    (malware-defense ?r - stig-rule)
    (patch-management ?r - stig-rule)
    (configuration-management ?r - stig-rule)
    (encryption ?r - stig-rule)
    (backup-and-recovery ?r - stig-rule)
    (incident-response ?r - stig-rule)
    (maintenance ?r - stig-rule)
    (physical-security ?r - stig-rule)

    ;; Technology mappings
    (applicable-to ?r - stig-rule ?tech - technology)
    (windows-os ?tech - operating-system)
    (rhel-os ?tech - operating-system)
    (kubernetes ?tech - container-platform)
    (apache-web ?tech - web-server)
    (nginx-web ?tech - web-server)
    (postgres-db ?tech - database)

    ;; Compliance state
    (rule-applicable ?r - stig-rule ?sys - system)
    (rule-compliant ?r - stig-rule ?sys - system)
    (rule-non-compliant ?r - stig-rule ?sys - system)

    ;; Scan state
    (scan-scheduled ?sys - system ?profile - scan-profile)
    (scan-completed ?sys - system)

    ;; Remediation
    (auto-remediation-available ?r - stig-rule)
    (auto-remediation-applied ?r - stig-rule ?sys - system)
    (remediation-tested ?r - stig-rule ?sys - system)

    ;; ATO
    (ato-granted ?sys - system)
    (pOAM-item ?finding - finding)
    (pOAM-overdue ?finding - finding)
    (c-io-approval ?sys - system)
    (acceptance-of-risk-documented ?sys - system)
  )

  (:action load-stig-benchmark
    :parameters (?b - benchmark ?sys - system)
    :precondition (and
      (benchmark-applicable ?b ?sys)
      (technology-identified ?sys ?tech)
    )
    :effect (forall (?r - stig-rule)
      (when (applicable-to ?r ?tech)
        (rule-applicable ?r ?sys)))
  )

  (:action execute-compliance-scan
    :parameters (?sys - system ?profile - scan-profile)
    :precondition (and
      (scan-scheduled ?sys ?profile)
      (not (scan-running ?sys))
    )
    :effect (and
      (scan-running ?sys)
      (forall (?r - stig-rule)
        (when (and (rule-applicable ?r ?sys) (auto-checkable ?r))
          (rule-checked ?r ?sys)))
      (scan-completed ?sys)
    )
  )

  (:action apply-auto-remediation
    :parameters (?r - stig-rule ?sys - system)
    :precondition (and
      (rule-non-compliant ?r ?sys)
      (auto-remediation-available ?r)
      (not (cat-i ?r))
    )
    :effect (and
      (auto-remediation-applied ?r ?sys)
      (remediation-tested ?r ?sys)
      (when (remediation-successful ?r ?sys)
        (rule-compliant ?r ?sys))
    )
  )

  (:action create-poam-item
    :parameters (?r - stig-rule ?sys - system)
    :precondition (rule-non-compliant ?r ?sys)
    :effect (and
      (pOAM-item (finding-for ?r ?sys))
      (when (cat-i ?r)
        (pOAM-critical (finding-for ?r ?sys)))
    )
  )

  (:action grant-ato
    :parameters (?sys - system ?ao - agent)
    :precondition (and
      (scan-completed ?sys)
      (compliance-score ?sys ?score)
      (>= ?score 90)
      (cat-i-open-count ?sys 0)
      (c-io-approval ?sys)
    )
    :effect (and
      (ato-granted ?sys)
      (ato-valid-for ?sys 365-days)
    )
  )

  (:action detect-poam-overdue
    :parameters (?f - finding)
    :precondition (and
      (pOAM-item ?f)
      (past-deadline ?f)
    )
    :effect (and
      (pOAM-overdue ?f)
      (ato-at-risk (system-for ?f))
    )
  )

  (:action revoke-ato
    :parameters (?sys - system ?ao - agent)
    :precondition (and
      (ato-granted ?sys)
      (or
        (new-cat-i-discovered ?sys)
        (multiple-poams-overdue ?sys)
        (security-incident-confirmed ?sys)
      )
    )
    :effect (and
      (not (ato-granted ?sys))
      (ato-revoked ?sys)
      (system-quarantine-required ?sys)
    )
  )
)
