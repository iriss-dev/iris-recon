-- Review fixture. This file is analyzed, never executed.
SELECT * FROM events WHERE message LIKE '%timeout%';
UPDATE events SET archived = 1;

-- An explicitly scoped write for comparison.
DELETE FROM events WHERE id = ?;
