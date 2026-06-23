;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Healthcare Domain: Compliance Audit Chain
;; Maps to: HIPAA Audit Controls 164.312(b), SOC 2 CC7.2, NIST 800-66
;; Purpose: Immutable audit trail with automated compliance verification
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain compliance-audit)
  (:requirements :strips :typing)

  (:types
    audit-event - object
    entity - object
    control - object
    regulation - object
    finding - object
    remediation - object
  )

  (:predicates
    ;; Event properties
    (event-timestamp ?e - audit-event)
    (event-actor ?e - audit-event ?ent - entity)
    (event-action ?e - audit-event)
    (event-resource ?e - audit-event ?res - object)
    (event-outcome ?e - audit-event)
    (event-integrity-hash ?e - audit-event)

    ;; Chain of custody
    (previous-event ?current - audit-event ?previous - audit-event)
    (chain-intact ?e - audit-event)
    (tamper-evident-seal ?e - audit-event)
    (blockchain-anchored ?e - audit-event)

    ;; Controls
    (control-implemented ?c - control)
    (control-tested ?c - control)
    (control-effective ?c - control)
    (control-automated ?c - control)
    (control-mapping ?c - control ?reg - regulation)

    ;; Regulations
    (hipaa-security ?reg - regulation)
    (hipaa-privacy ?reg - regulation)
    (hitech-breach ?reg - regulation)
    (cms-ffs ?reg - regulation)
    (joint-commission ?reg - regulation)
    (state-law ?reg - regulation)

    ;; Findings
    (finding-open ?f - finding)
    (finding-closed ?f - finding)
    (finding-severity ?f - finding ?level)
    (finding-associated-control ?f - finding ?c - control)
    (remediation-planned ?f - finding ?r - remediation)
    (remediation-verified ?f - finding)

    ;; Access patterns
    (phi-accessed ?e - audit-event)
    (minimum-necessary-violation ?e - audit-event)
    (unauthorized-access-attempt ?e - audit-event)
    (after-hours-access ?e - audit-event)
    (bulk-access-pattern ?e - audit-event)

    ;; Alerts
    (alert-generated ?e - audit-event)
    (alert-escalated ?e - audit-event)
    (privacy-officer-notified ?e - audit-event)
    (security-officer-notified ?e - audit-event)
    (ocr-reportable ?e - audit-event)
  )

  (:action log-audit-event
    :parameters (?e - audit-event ?actor - entity ?action ?resource - object ?prev - audit-event)
    :precondition (and
      (chain-intact ?prev)
      (previous-event ?e ?prev)
      (event-integrity-hash ?e)
    )
    :effect (and
      (event-actor ?e ?actor)
      (event-action ?e)
      (event-resource ?e ?resource)
      (chain-intact ?e)
      (tamper-evident-seal ?e)
    )
  )

  (:action detect-anomaly
    :parameters (?e - audit-event)
    :precondition (and
      (chain-intact ?e)
      (or
        (minimum-necessary-violation ?e)
        (unauthorized-access-attempt ?e)
        (after-hours-access ?e)
        (bulk-access-pattern ?e)
      )
    )
    :effect (and
      (alert-generated ?e)
      (finding-open (finding-for ?e))
      (privacy-officer-notified ?e)
    )
  )

  (:action escalate-to-ocr
    :parameters (?e - audit-event)
    :precondition (and
      (alert-generated ?e)
      (ocr-reportable ?e)
      (phi-accessed ?e)
      (finding-severity (finding-for ?e) critical)
    )
    :effect (and
      (alert-escalated ?e)
      (breach-notification-required ?e)
      (security-officer-notified ?e)
    )
  )

  (:action verify-control-effectiveness
    :parameters (?c - control ?reg - regulation)
    :precondition (and
      (control-implemented ?c)
      (control-mapping ?c ?reg)
    )
    :effect (and
      (control-tested ?c)
      (when (automated-test-passed ?c)
        (control-effective ?c))
    )
  )

  (:action close-finding
    :parameters (?f - finding ?r - remediation)
    :precondition (and
      (finding-open ?f)
      (remediation-planned ?f ?r)
      (remediation-implemented ?r)
      (remediation-verified ?f)
    )
    :effect (and
      (finding-closed ?f)
      (not (finding-open ?f))
      (audit-logged finding-closure ?f ?r)
    )
  )

  (:action anchor-to-blockchain
    :parameters (?e - audit-event)
    :precondition (and
      (chain-intact ?e)
      (not (blockchain-anchored ?e))
    )
    :effect (and
      (blockchain-anchored ?e)
      (immutable-proof-created ?e)
    )
  )
)
