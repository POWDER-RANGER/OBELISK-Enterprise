;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Healthcare Domain: Patient Data Routing
;; Maps to: HIPAA 164.502 (Minimum Necessary), 164.524 (Access), 45 CFR 164
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain patient-data-routing)
  (:requirements :strips :typing :conditional-effects)

  (:types
    data-element - object
    system - object
    user - agent
    purpose - object
    transmission-channel - object
    classification-level - object
  )

  (:types
    ehr - system
    pacs - system
    lab-system - system
    pharmacy - system
    hie - system
    patient-portal - system
    research-db - system
    billing - system
  )

  (:predicates
    ;; Data classification
    (classified-as ?de - data-element ?cl - classification-level)
    (phi-direct-identifier ?de - data-element)
    (phi-quasi-identifier ?de - data-element)
    (phi-sensitive ?de - data-element)
    (de-identified-safe-harbor ?de - data-element)
    (encrypted-field ?de - data-element)

    ;; System security levels
    (system-classification ?sys - system ?cl - classification-level)
    (hitrust-certified ?sys - system)
    (end-to-end-encrypted ?sys - system)
    (baa-signed ?sys - system)
    (on-premise ?sys - system)
    (cloud-hosted ?sys - system)

    ;; Routing rules
    (allowed-flow ?from - system ?to - system ?purpose)
    (prohibited-flow ?from - system ?to - system)
    (requires-consent ?from - system ?to - system)
    (requires-minimum-necessary ?from - system ?to - system)
    (requires-de-identification ?from - system ?to - system)

    ;; Audit
    (flow-logged ?de - data-element ?from - system ?to - system)
    (dlp-scan-passed ?de - data-element)
  )

  (:action route-phi-data
    :parameters (?de - data-element ?from - system ?to - system ?ch - transmission-channel ?purpose)
    :precondition (and
      (classified-as ?de phi)
      (not (prohibited-flow ?from ?to))
      (allowed-flow ?from ?to ?purpose)
      (baa-signed ?from)
      (baa-signed ?to)
      (end-to-end-encrypted ?to)
      (dlp-scan-passed ?de)
      (requires-minimum-necessary ?from ?to)
    )
    :effect (and
      (flow-logged ?de ?from ?to)
    )
  )

  (:action route-to-research
    :parameters (?de - data-element ?from - system ?to - research-db ?ch - transmission-channel)
    :precondition (and
      (classified-as ?de phi)
      (de-identified-safe-harbor ?de)
      (requires-de-identification ?from ?to)
      (baa-signed ?to)
    )
    :effect (and
      (flow-logged ?de ?from ?to)
      (research-data-available ?de)
    )
  )
)
