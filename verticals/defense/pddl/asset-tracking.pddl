;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Defense Domain: Asset Tracking
;; Maps to: NIST 800-53 CM-8, DFARS 252.204-7012, DoD 8500.2
;; Purpose: Track classified assets with chain of custody
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain asset-tracking)
  (:requirements :strips :typing)

  (:types
    asset - object
    custodian - agent
    location - place
    classification-level - object
    transfer-request - object
    audit-trail - object
  )

  (:types
    physical-asset - asset
    digital-asset - asset
    document - physical-asset
    hardware - physical-asset
    media - physical-asset
    file - digital-asset
    database - digital-asset
    vm-instance - digital-asset
  )

  (:predicates
    ;; Classification
    (classified-confidential ?a - asset)
    (classified-secret ?a - asset)
    (classified-top-secret ?a - asset)
    (classified-ts-sci ?a - asset)
    (classified-sap ?a - asset)
    (classification-marked ?a - asset)
    (portion-marked ?a - asset)
    (contains-cui ?a - asset)
    (contains-cdi ?a - asset)
    (contains-itar ?a - asset)

    ;; Custody
    (custodian-assigned ?a - asset ?c - custodian)
    (custodian-cleared ?c - custodian ?level - classification-level)
    (need-to-know ?c - custodian ?a - asset)
    (two-person-integrity ?a - asset)
    (two-person-present ?a - asset)

    ;; Location
    (located-at ?a - asset ?loc - location)
    (authorized-location ?a - asset ?loc - location)
    (scif ?loc - location)
    (secure-vault ?loc - location)
    (armed-guard-post ?loc - location)
    (audit-log-enabled ?loc - location)

    ;; Transfer
    (transfer-approved ?req - transfer-request)
    (transfer-authorized-by ?req - transfer-request ?auth - agent)
    (secure-transport-arranged ?req - transfer-request)
    (chain-of-custody-intact ?a - asset)
    (handoff-receipt-signed ?a - asset ?from - custodian ?to - custodian)
    (courier-cleared ?c - custodian ?level - classification-level)

    ;; Digital asset controls
    (encrypted-at-rest ?a - digital-asset)
    (encrypted-in-transit ?a - digital-asset)
    (hardware-token-required ?a - digital-asset)
    (biometric-auth-required ?a - digital-asset)
    (session-timeout-configured ?a - digital-asset)
    (audit-log-immutable ?a - digital-asset)
    (data-loss-prevention-enabled ?a - digital-asset)

    ;; Lifecycle
    (asset-inventoried ?a - asset)
    (asset-decommissioned ?a - asset)
    (sanitization-complete ?a - asset)
    (destruction-verified ?a - asset)
    (disposal-record-retained ?a - asset)
  )

  (:action check-in-asset
    :parameters (?a - asset ?loc - location ?c - custodian)
    :precondition (and
      (custodian-cleared ?c (classification-of ?a))
      (need-to-know ?c ?a)
      (authorized-location ?a ?loc)
      (audit-log-enabled ?loc)
    )
    :effect (and
      (located-at ?a ?loc)
      (custodian-assigned ?a ?c)
      (chain-of-custody-intact ?a)
      (asset-inventoried ?a)
      (audit-logged check-in ?a ?c ?loc)
    )
  )

  (:action transfer-custody
    :parameters (?a - asset ?from - custodian ?to - custodian ?loc - location)
    :precondition (and
      (custodian-assigned ?a ?from)
      (custodian-cleared ?to (classification-of ?a))
      (need-to-know ?to ?a)
      (or (not (two-person-integrity ?a)) (two-person-present ?a))
      (handoff-receipt-signed ?a ?from ?to)
    )
    :effect (and
      (not (custodian-assigned ?a ?from))
      (custodian-assigned ?a ?to)
      (chain-of-custody-intact ?a)
      (audit-logged custody-transfer ?a ?from ?to ?loc)
    )
  )

  (:action transfer-to-scif
    :parameters (?a - asset ?from - location ?to - location ?c - custodian)
    :precondition (and
      (classified-ts-sci ?a)
      (scif ?to)
      (located-at ?a ?from)
      (custodian-cleared ?c ts-sci)
      (transfer-approved (transfer-req ?a ?from ?to))
      (secure-transport-arranged (transfer-req ?a ?from ?to))
      (courier-cleared ?c ts-sci)
    )
    :effect (and
      (located-at ?a ?to)
      (audit-logged scif-transfer ?a ?from ?to ?c)
    )
  )

  (:action decommission-asset
    :parameters (?a - asset ?c - custodian)
    :precondition (and
      (custodian-assigned ?a ?c)
      (decommission-authorized ?a)
      (sanitization-complete ?a)
      (or (destruction-verified ?a) (reclassification-approved ?a))
    )
    :effect (and
      (asset-decommissioned ?a)
      (disposal-record-retained ?a)
      (not (custodian-assigned ?a ?c))
      (audit-logged decommission ?a ?c)
    )
  )

  (:action detect-custody-anomaly
    :parameters (?a - asset)
    :precondition (and
      (or
        (not (chain-of-custody-intact ?a))
        (unauthorized-location-detected ?a)
        (after-hours-access ?a)
      )
    )
    :effect (and
      (security-alert-generated ?a)
      (sso-notified ?a)
      (fso-notified ?a)
    )
  )
)
