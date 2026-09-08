-- Native 0027: enforce the run-terminal retention boundary for visible reasoning chunks.
-- Active runs retain replayable reasoning until they atomically commit any terminal state. Historical
-- terminal rows are reduced to the same fixed marker; sequence, event identity, and terminal facts stay intact.

UPDATE public.run_events AS reasoning_event
SET payload = jsonb_build_object(
    'channel', 'reasoning',
    'delta', '',
    'retained', false
)
FROM public.runs AS run
WHERE reasoning_event.run_id = run.run_id
  AND reasoning_event.event_type = 'semantic_chunk'
  AND reasoning_event.payload->>'channel' = 'reasoning'
  AND run.status IN ('completed', 'failed', 'cancelled', 'reconciliation_required')
  AND reasoning_event.payload IS DISTINCT FROM jsonb_build_object(
      'channel', 'reasoning',
      'delta', '',
      'retained', false
  );
