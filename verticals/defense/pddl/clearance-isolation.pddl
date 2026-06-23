;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Defense Domain: Clearance-Level Data Isolation
;; Maps to: NIST 800-53 AC-3, AC-4, SC-7, CNSSI 1253
;; Purpose: Enforce mandatory access control (MAC) based on clearance levels
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain clearance-isolation)
  (:requirements :strips :typing :conditional-effects)

  (:types
    subject - agent
    object - object
    clearance-level - object
    compartment - object
    classification - object
    network-segment - object
    cross-domain-solution - object
  )

  (:types
    user - subject
    process - subject
    service-account - subject
  )

  (:predicates
    ;; Clearance levels (dominance hierarchy)
    (clearance ?s - subject ?cl - clearance-level)
    (classification ?o - object ?cl - classification-level)
    (dominates ?cl1 - clearance-level ?cl2 - classification-level)

    ;; Clearance levels
    (level-public)
    (level-cui)
    (level-confidential)
    (level-secret)
    (level-top-secret)
    (level-ts-sci ?comp - compartment)

    ;; Compartments (SCI)
    (read-in ?s - subject ?comp - compartment)
    (compartment-hvl)
    (compartment-comint)
    (compartment-imint)
    (compartment-sigint)
    (compartment-talent-keyhole)
    (compartment-orcon)

    ;; Network segmentation
    (network-niprnet)
    (network-siprnet)
    (network-jwics)
    (network-enclave ?net - network-segment)
    (segment-isolation-verified ?net - network-segment)

    ;; Cross-domain solutions
    (cds-approved ?cds - cross-domain-solution)
    (cds-accredited ?cds - cross-domain-solution ?level)
    (transfer-approved-by-ao ?cds - cross-domain-solution)
    (one-way-only ?cds - cross-domain-solution)
    (content-filter-active ?cds - cross-domain-solution)
    (malware-scan-enabled ?cds - cross-domain-solution)

    ;; Access decisions
    (read-allowed ?s - subject ?o - object)
    (write-allowed ?s - subject ?o - object)

    ;; Bell-LaPadula properties
    (no-read-up ?s - subject ?o - object)
    (no-write-down ?s - subject ?o - object)

    ;; Audit
    (access-logged ?s - subject ?o - object ?action)
    (denial-logged ?s - subject ?o - object)
  )

  (:action mac-read
    :parameters (?s - subject ?o - object)
    :precondition (and
      (clearance ?s ?sc)
      (classification ?o ?oc)
      (dominates ?sc ?oc)
      (no-read-up ?s ?o)
      (session-authenticated ?s)
    )
    :effect (and
      (read-allowed ?s ?o)
      (access-logged ?s ?o read)
    )
  )

  (:action mac-write
    :parameters (?s - subject ?o - object)
    :precondition (and
      (clearance ?s ?sc)
      (classification ?o ?oc)
      (dominates ?sc ?oc)
      (no-write-down ?s ?o)
    )
    :effect (and
      (write-allowed ?s ?o)
      (access-logged ?s ?o write)
    )
  )

  (:action sci-read
    :parameters (?s - subject ?o - object ?comp - compartment)
    :precondition (and
      (clearance ?s level-ts-sci)
      (read-in ?s ?comp)
      (object-ts-sci ?o ?comp)
    )
    :effect (and
      (read-allowed ?s ?o)
      (access-logged ?s ?o sci-read)
    )
  )

  (:action cross-domain-transfer
    :parameters (?cds - cross-domain-solution ?o - object ?from-net - network-segment ?to-net - network-segment)
    :precondition (and
      (cds-approved ?cds)
      (content-filter-active ?cds)
      (malware-scan-enabled ?cds)
      (or (one-way-only ?cds) (bidirectional-approved ?cds))
    )
    :effect (and
      (transfer-approved ?o ?from-net ?to-net)
      (sanitized-metadata ?o)
      (audit-logged cross-domain-transfer ?o ?cds)
    )
  )

  (:action deny-access
    :parameters (?s - subject ?o - object)
    :precondition (and
      (session-authenticated ?s)
      (or
        (not (dominates (clearance ?s) (classification ?o)))
        (and (object-ts-sci ?o ?comp) (not (read-in ?s ?comp)))
      )
    )
    :effect (and
      (not (read-allowed ?s ?o))
      (denial-logged ?s ?o)
    )
  )
)
