;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Finance Domain: UDAAP Monitoring
;; Maps to: Dodd-Frank 1031, CFPB Bulletin 2012-03, Regulation AA
;; Purpose: Detect Unfair, Deceptive, or Abusive Acts or Practices
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain udaap-monitoring)
  (:requirements :strips :typing :conditional-effects)

  (:types
    consumer - subject
    product - object
    marketing-material - object
    disclosure - object
    practice - action
    complaint - object
    regulator - entity
  )

  (:predicates
    ;; Consumer attributes
    (vulnerable-consumer ?c - consumer)
    (limited-english-proficiency ?c - consumer)
    (servicemember ?c - consumer)
    (elderly-consumer ?c - consumer)
    (financially-distressed ?c - consumer)

    ;; Product attributes
    (high-fee-product ?p - product)
    (complex-product ?p - product)
    (predatory-product ?p - product)

    ;; UDAAP categories
    (unfair-practice ?pr - practice)
    (deceptive-practice ?pr - practice)
    (abusive-practice ?pr - practice)

    ;; Marketing
    (misleading-claim ?m - marketing-material)
    (omission-of-material-fact ?m - marketing-material)
    (pressure-tactics ?m - marketing-material)

    ;; Disclosures
    (clear-and-conspicuous ?d - disclosure)
    (timing-adequate ?d - disclosure)
    (cost-fully-disclosed ?d - disclosure)
    (risk-disclosed ?d - disclosure)

    ;; Monitoring
    (consumer-harm-detected ?c - consumer)
    (pattern-of-harm-detected)
    (complaint-trend-detected ?p - product)

    ;; Enforcement
    (practice-investigated ?pr - practice)
    (practice-prohibited ?pr - practice)
    (remediation-required ?pr - practice)
    (consumer-restitution-ordered ?c - consumer)
    (consent-order-issued)
  )

  (:action evaluate-unfairness
    :parameters (?pr - practice ?p - product ?c - consumer)
    :precondition (and
      (causes-substantial-injury ?pr ?c)
      (not (reasonably-avoidable ?c ?pr))
      (not (outweighed-by-benefit ?pr))
    )
    :effect (and
      (unfair-practice ?pr)
      (consumer-harm-detected ?c)
      (audit-logged unfair-practice-detected ?pr ?c)
    )
  )

  (:action evaluate-deception
    :parameters (?pr - practice ?m - marketing-material ?c - consumer)
    :precondition (and
      (or (misleading-claim ?m) (omission-of-material-fact ?m))
      (reasonable-consumer-misled ?c ?m)
      (material-to-decision ?m)
    )
    :effect (and
      (deceptive-practice ?pr)
      (consumer-harm-detected ?c)
      (audit-logged deceptive-practice-detected ?pr ?c)
    )
  )

  (:action evaluate-abusiveness
    :parameters (?pr - practice ?p - product ?c - consumer)
    :precondition (and
      (or
        (materially-interferes-understanding ?pr ?c)
        (takes-unreasonable-advantage ?pr ?c)
      )
      (or
        (lack-of-understanding ?c ?p)
        (inability-protect-interests ?c ?pr)
        (reasonable-reliance ?c ?pr)
      )
    )
    :effect (and
      (abusive-practice ?pr)
      (consumer-harm-detected ?c)
      (audit-logged abusive-practice-detected ?pr ?c)
    )
  )

  (:action detect-vulnerable-consumer-harm
    :parameters (?pr - practice ?c - consumer)
    :precondition (and
      (or (vulnerable-consumer ?c) (elderly-consumer ?c) (servicemember ?c))
      (or (unfair-practice ?pr) (deceptive-practice ?pr) (abusive-practice ?pr))
    )
    :effect (and
      (pattern-of-harm-detected)
      (practice-escalated ?pr)
      (regulatory-reporting-required ?pr)
    )
  )

  (:action prohibit-practice
    :parameters (?pr - practice)
    :precondition (and
      (or
        (pattern-of-harm-detected)
        (regulatory-inquiry-received cfpb)
      )
    )
    :effect (and
      (practice-prohibited ?pr)
      (immediate-cessation-required ?pr)
      (compliance-training-required)
    )
  )
)
