;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; OBELISK Finance Domain: Trade Surveillance
;; Maps to: SEC 17a-4, FINRA 3110, MiFID II, Dodd-Frank 747, MAR
;; Purpose: Detect market manipulation, insider trading, and abusive practices
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(define (domain trade-surveillance)
  (:requirements :strips :typing :conditional-effects)

  (:types
    trader - agent
    trade - event
    security - instrument
    order - action
    alert - finding
    market - venue
  )

  (:predicates
    ;; Trader attributes
    (registered-rep ?t - trader)
    (series-7-licensed ?t - trader)
    (series-63-licensed ?t - trader)
    (insider-status ?t - trader ?sec - security)
    (personal-account-approved ?t - trader)

    ;; Trade attributes
    (trade-executed ?tr - trade ?t - trader ?sec - security ?m - market)

    ;; Surveillance patterns
    (layering-pattern ?trades - trade)
    (momentum-ignition ?trades - trade)
    (wash-trading ?t1 - trader ?t2 - trader)
    (front-running ?t - trader)
    (insider-trading-pattern ?t - trader ?sec - security)
    (marking-the-close ?tr - trade)

    ;; Restrictions
    (restricted-security ?sec - security ?t - trader)
    (blackout-period-active ?sec - security)
    (pre-clearance-required ?sec - security)
    (pre-cleared ?t - trader ?sec - security)

    ;; Surveillance actions
    (trade-captured ?tr - trade)
    (alert-generated ?a - alert ?tr - trade)
    (alert-escalated ?a - alert)
    (suspicious-activity-reported ?a - alert)
    (trade-reversed ?tr - trade)
    (trader-suspended ?t - trader)
  )

  (:action execute-trade
    :parameters (?t - trader ?sec - security ?m - market ?tr - trade ?ord - order)
    :precondition (and
      (registered-rep ?t)
      (series-7-licensed ?t)
      (not (restricted-security ?sec ?t))
      (not (blackout-period-active ?sec))
      (or (not (pre-clearance-required ?sec)) (pre-cleared ?t ?sec))
      (trade-captured ?tr)
    )
    :effect (trade-executed ?tr ?t ?sec ?m)
  )

  (:action detect-layering
    :parameters (?t - trader ?sec - security ?trades - trade)
    :precondition (and
      (layering-pattern ?trades)
      (forall (?tr - trade) (trade-executed ?tr ?t ?sec))
    )
    :effect (and
      (alert-generated layering-alert ?trades)
      (suspicious-activity-reported layering-alert)
    )
  )

  (:action detect-front-running
    :parameters (?t - trader ?client-order - order ?proprietary-trade - trade)
    :precondition (and
      (front-running ?t)
      (timestamp-before ?proprietary-trade client-order)
      (same-security client-order proprietary-trade)
    )
    :effect (and
      (alert-escalated frontrun-alert)
      (trader-suspended ?t)
      (suspicious-activity-reported frontrun-alert)
    )
  )

  (:action detect-insider-trading
    :parameters (?t - trader ?sec - security ?tr - trade)
    :precondition (and
      (insider-status ?t ?sec)
      (not (chinese-wall-access ?t ?sec))
      (trade-executed ?tr ?t ?sec)
      (material-nonpublic-information ?t ?sec)
    )
    :effect (and
      (alert-escalated insider-alert ?tr)
      (insider-trading-pattern ?t ?sec)
      (suspicious-activity-reported insider-alert)
      (trade-reversed ?tr)
      (trader-suspended ?t)
    )
  )

  (:action file-sar
    :parameters (?a - alert)
    :precondition (and
      (alert-escalated ?a)
      (suspicious-activity-reported ?a)
      (within-30-days ?a)
    )
    :effect (and
      (sar-filed ?a)
      (finCEN-notified ?a)
    )
  )
)
