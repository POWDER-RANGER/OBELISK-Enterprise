;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Healthcare Domain: Clinical Workflow Scheduling
;; Maps to: HIPAA Security Rule 164.312, HITECH, Joint Commission Standards
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain clinical-workflow)
  (:requirements :strips :typing :negative-preconditions :conditional-effects)

  (:types
    provider - agent
    patient - subject
    appointment - event
    resource - asset
    record - document
    department - location
    timeslot - temporal
  )

  (:predicates
    ;; Identity & Authentication
    (authenticated ?p - provider)
    (verified-identity ?p - provider)
    (mfa-complete ?p - provider)
    (session-valid ?p - provider)

    ;; Authorization
    (authorized-department ?p - provider ?d - department)
    (role-physician ?p - provider)
    (role-nurse ?p - provider)
    (role-admin ?p - provider)

    ;; Patient Consent
    (consent-on-file ?pt - patient)
    (consent-explicit ?pt - patient ?purpose)
    (consent-revoked ?pt - patient)

    ;; Record Classification
    (phi ?r - record)
    (psychiatric ?r - record)
    (substance-abuse ?r - record)
    (hiv-status ?r - record)
    (genetic-data ?r - record)

    ;; Data Access
    (can-read ?p - provider ?r - record)
    (break-glass-active ?p - provider)

    ;; Appointment
    (scheduled ?a - appointment ?pt - patient ?d - department ?t - timeslot)
    (checked-in ?pt - patient)
    (in-session ?pt - patient ?p - provider)
    (completed ?a - appointment)

    ;; Audit
    (audit-logged ?action ?p - provider ?r - record)

    ;; Compliance
    (hipaa-minimum-necessary-met ?action)
    (consent-verified ?action)
    (baa-in-place ?department)
    (phi-encrypted ?r - record)
    (training-current ?p - provider)
  )

  (:action schedule-appointment
    :parameters (?p - provider ?pt - patient ?d - department ?t - timeslot ?res - resource)
    :precondition (and
      (authenticated ?p)
      (verified-identity ?p)
      (session-valid ?p)
      (authorized-department ?p ?d)
      (or (role-physician ?p) (role-nurse ?p) (role-admin ?p))
      (training-current ?p)
      (consent-on-file ?pt)
      (not (consent-revoked ?pt))
      (baa-in-place ?d)
    )
    :effect (and
      (scheduled appointment-1 ?pt ?d ?t)
      (audit-logged schedule-appointment ?p (record-for ?pt))
    )
  )

  (:action access-patient-record
    :parameters (?p - provider ?pt - patient ?r - record)
    :precondition (and
      (authenticated ?p)
      (mfa-complete ?p)
      (session-valid ?p)
      (or (can-read ?p ?r) (break-glass-active ?p))
      (or
        (and (not (phi ?r)) (not (psychiatric ?r)))
        (and (phi ?r) (training-current ?p))
        (and (psychiatric ?r) (consent-explicit ?pt psychiatric-access))
      )
    )
    :effect (and
      (can-read ?p ?r)
      (audit-logged access-patient-record ?p ?r)
      (hipaa-minimum-necessary-met access-patient-record)
    )
  )
)
