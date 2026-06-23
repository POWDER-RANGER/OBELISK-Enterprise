;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Finance Domain: Model Validation (SR 11-7 / EU AI Act)
;; Maps to: SR 11-7, SS1/23, EU AI Act Title III, GDPR Article 22
;; Purpose: Govern AI/ML model lifecycle in financial services
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain model-validation)
  (:requirements :strips :typing)

  (:types
    model - object
    developer - agent
    validator - agent
    risk-committee - entity
    dataset - object
    metric - object
    bias-test - object
    stress-scenario - object
    deployment-stage - object
  )

  (:predicates
    ;; Model attributes
    (model-name ?m - model)
    (model-purpose ?m - model)
    (model-type ?m - model)
    (model-complexity ?m - model)
    (sr11-7-applicable ?m - model)
    (eu-ai-act-high-risk ?m - model)

    ;; Development lifecycle
    (concept-paper-approved ?m - model)
    (development-complete ?m - model)
    (self-validation-done ?m - model)
    (independent-validation-done ?m - model)
    (oos-testing-done ?m - model)
    (oot-testing-done ?m - model)
    (stress-testing-done ?m - model)
    (bias-testing-done ?m - model)
    (explainability-review-done ?m - model)
    (documentation-complete ?m - model)
    (risk-committee-approved ?m - model)

    ;; Bias & Fairness
    (disparate-impact-tested ?m - model)
    (protected-class-tested ?m - model)
    (fairness-metric-acceptable ?m - model)
    (adversarial-testing-done ?m - model)
    (red-team-review-done ?m - model)

    ;; Monitoring
    (production-monitoring-active ?m - model)
    (annual-validation-scheduled ?m - model)
    (performance-degradation-detected ?m - model)
    (model-drift-detected ?m - model)

    ;; Governance
    (mrm-policy-compliant ?m - model)
    (three-lines-defense-implemented ?m - model)
    (inventory-registered ?m - model)
    (owner-assigned ?m - model ?dev - developer)
    (validator-assigned ?m - model ?val - validator)

    ;; Deployment
    (approved-for-production ?m - model)
    (deployed-to-production ?m - model)
    (shadow-mode-testing ?m - model)
    (champion-challenger-active ?m - model)
    (rollback-plan-documented ?m - model)
    (emergency-kill-switch-tested ?m - model)
  )

  (:action submit-for-validation
    :parameters (?m - model ?dev - developer)
    :precondition (and
      (owner-assigned ?m ?dev)
      (development-complete ?m)
      (self-validation-done ?m)
      (model-documented ?m)
    )
    :effect (submitted-for-validation ?m)
  )

  (:action perform-independent-validation
    :parameters (?m - model ?val - validator)
    :precondition (and
      (submitted-for-validation ?m)
      (validator-assigned ?m ?val)
      (independent-from-developer ?val)
    )
    :effect (and
      (independent-validation-done ?m)
      (conceptual-soundness-validated ?m)
      (methodology-validated ?m)
    )
  )

  (:action perform-bias-testing
    :parameters (?m - model)
    :precondition (and
      (independent-validation-done ?m)
      (or (sr11-7-applicable ?m) (eu-ai-act-high-risk ?m))
    )
    :effect (and
      (bias-testing-done ?m)
      (disparate-impact-tested ?m)
      (protected-class-tested ?m)
    )
  )

  (:action approve-for-production
    :parameters (?m - model ?committee - risk-committee)
    :precondition (and
      (independent-validation-done ?m)
      (oos-testing-done ?m)
      (oot-testing-done ?m)
      (stress-testing-done ?m)
      (bias-testing-done ?m)
      (explainability-review-done ?m)
      (documentation-complete ?m)
      (three-lines-defense-implemented ?m)
      (emergency-kill-switch-tested ?m)
    )
    :effect (approved-for-production ?m)
  )

  (:action deploy-with-monitoring
    :parameters (?m - model)
    :precondition (and
      (approved-for-production ?m)
      (production-monitoring-active ?m)
      (annual-validation-scheduled ?m)
    )
    :effect (and
      (deployed-to-production ?m)
      (shadow-mode-testing ?m)
      (champion-challenger-active ?m)
    )
  )

  (:action trigger-emergency-rollback
    :parameters (?m - model)
    :precondition (and
      (deployed-to-production ?m)
      (or
        (performance-degradation-detected ?m)
        (model-drift-detected ?m)
      )
    )
    :effect (and
      (model-rolled-back ?m)
      (previous-version-activated ?m)
      (incident-logged ?m)
    )
  )
)
