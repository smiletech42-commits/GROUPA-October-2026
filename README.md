# GROUP A
Adisa Taiwo
--- create database internship;
use internship;
select * from devices;
select * from employees;
select * from ip_reputation;
select * from login_logs;
UPDATE login_logs
SET login_hour = HOUR(login_timestamp);
ALTER TABLE login_logs
ADD COLUMN login_hour INT;
select * from security_alerts;

 --- How many login events are recorded in the database?
select count(*) as total_login_events from login_logs;

--- What period does the dataset cover?
SELECT
    MIN(login_timestamp) AS first_login,
    MAX(login_timestamp) AS last_login
FROM login_logs;

--- What proportion of login attempts succeeded, and what proportion failed?
SELECT
    login_status,
    COUNT(*) AS total_attempts,
    ROUND(
        COUNT(*) * 100.0 / (SELECT COUNT(*) FROM login_logs),
        2
    ) AS percentage
FROM login_logs
GROUP BY login_status;

--- Which days of the week experience the highest number of failed login attempts?
SELECT
    DAYNAME(login_timestamp) AS day_of_week,
    COUNT(*) AS failed_attempts
FROM login_logs
WHERE login_status = 'Failed'
GROUP BY DAYNAME(login_timestamp)
ORDER BY failed_attempts DESC;

--- Which hours of the day have the highest volume of failed logins?

SELECT
    login_hour,
    COUNT(*) AS failed_attempts
FROM login_logs
WHERE login_status = 'Failed'
GROUP BY login_hour
ORDER BY failed_attempts DESC;

--- Which employee accounts have the highest number of failed login attempts?

SELECT
    e.employee_name,
    l.employee_id,
    COUNT(*) AS failed_attempts
FROM login_logs AS l
JOIN employees AS e
    ON l.employee_id = e.employee_id
WHERE l.login_status = 'Failed'
GROUP BY e.employee_name, l.employee_id
ORDER BY failed_attempts DESC;

--- Can you identify accounts with repeated failed logins followed by a successful login? 

  WITH login_sequence AS (
    SELECT
        employee_id,
        login_timestamp,
        login_status,
        LAG(login_status) OVER (
            PARTITION BY employee_id
            ORDER BY login_timestamp
        ) AS previous_status,
        LAG(login_status, 2) OVER (
            PARTITION BY employee_id
            ORDER BY login_timestamp
        ) AS status_two_events_before
    FROM login_logs
)
SELECT *
FROM login_sequence
WHERE login_status = 'Success'
  AND previous_status = 'Failed'
  AND status_two_events_before = 'Failed';
