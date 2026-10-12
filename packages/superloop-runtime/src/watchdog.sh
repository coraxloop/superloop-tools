# Embedded container payload: the runtime client is replaced by the engine,
# preserving CALLER_PID across exec in the shared host PID namespace.
exec 3<&0
"$@" <&3 & p=$!
( while kill -0 "$CALLER_PID" 2>/dev/null; do sleep 3; done; kill -TERM "$p" 2>/dev/null; sleep 10; kill -KILL "$p" 2>/dev/null ) & w=$!
wait "$p"; rc=$?
kill "$w" 2>/dev/null
exit "$rc"
