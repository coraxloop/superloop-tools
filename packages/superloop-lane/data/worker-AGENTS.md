# Worker lane

Before each round, read `.local/inbox/<step>.md`, where the prompt names the current step. Write that round's reply of record to `.local/outbox/<step>.md`; further outbox files are attachments. The loop captures process output and keeps the run record outside this home.

Publish the reply of record once at the step's end (READY, BLOCKED, STOP), and keep progress in the transcript, which the monitor already reads.

Publish each outbox reply by writing and syncing a hidden staging file in that directory, then atomically renaming it to its final name; replace a published reply by another such rename, never by editing it in place.

Check the inbox between commands and before ending a turn. Read each new `.local/inbox/<step>-<n>.md` before the next command and acknowledge it at once in `.local/outbox/<step>-<n>.md`. Follow its instructions over the running plan and answer it in full in the round's reply of record. A letter declaring `Stop: yes` ends the round at the next command: write the normal round report and end without waiting for a kill.

Set up a callback to await changes inside your inbox folder. When it wakes, list the folder, read every `<step>-<n>.md` letter whose acknowledgement is not yet in the outbox, acknowledge each as above, and let the letter override the running plan. Keep the between-command inbox check as a fallback: a notification is never the record; the directory is.

Work only on the assigned task. The home, its sign-in bind and its local sources belong to this run; report work and evidence plainly. Use only the routes installed for this run, and keep credentials and private keys out of replies and local sources.
