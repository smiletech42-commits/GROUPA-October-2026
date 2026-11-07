# GROUP A
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
 
 --- creating the database for northstar_service
create database northstar_services;
use northstar_services;

--- showing all tables for northstar_service database
show tables;

--- inspecting login_logs records
select * from login_logs
limit 10;

--- inspecting ip reputation records 
select * from ip_reputation
limit 10;

--- IP Address that generated the highest number of login attempts 
select ip_address, count(*) AS total_attempts 
from login_logs
where ip_address IS NOT NULL 
group by ip_address 
order by total_attempts DESC;

--- IP Address that generated the highest number of failed login attempts 
select ip_address, count(*) as failed_attempts 
from login_logs 
where login_status = 'Failed' and ip_address is not null 
group by ip_address 
order by failed_attempts desc;

--- ip reputation information about addresses associated with successful logins

select
		r.risk_level, 
        r.country,
        count(*) as total_attempts,
        sum(l.login_status = 'Success') as successful_logins,
        sum(l.login_status = 'Failed') as failed_logins
from login_logs as l
join ip_reputation as r 
        on l.ip_address = r.ip_address 
group by r.risk_level, r.country 
order by total_attempts desc;
        
 --- successful logins associated with high risk ip addresses 
 
 select 
        l.ip_address,
        l.login_status, 
        r.risk_level,
        r.country,
        r.reputation_note
from login_logs as l
join ip_reputation as r 
     on l.ip_address = r.ip_address
where l.login_status = 'Success' and r.risk_level = 'High Risk'; 

--- Countries or threat categories that appear most frequently in the available records

select 
	  country,
      count(*) as ip_record_count
from ip_reputation
group by country 
order by ip_record_count desc;

select 
      risk_level,
      count(*) as ip_record_count
from ip_reputation
group by risk_level
order by ip_record_count desc;

--- Reasonable Rule For Flagging potentially suspicious login activity

select 
      l.ip_address,
      count(*)  as total_attempts,
      sum(l.login_status = 'Failed') as failed_attempts,
      sum(l.login_status = 'Success') as successful_logins,
      r.risk_level,
      r.reputation_note
from login_logs as l
left join ip_reputation as r
		on l.ip_address = r.ip_address 
where l.ip_address is not null
group  by 
         l.ip_address,
         r.risk_level,
         r.reputation_note
having r.risk_level = 'High Risk'
       or sum(l.login_status = 'Failed') >= 5
order by failed_attempts desc;

-- create database
create database internship;
use internship;
select * from devices;
select * from employees;
select * from ip_reputation;
select * from login_logs;
select * from security_alerts;

select employees.employee_id, employees.employee_name, employees.department, employees.job_role,
count(distinct login_logs.device_id) as device_count
from employees join login_logs on login_logs.employee_id = employees.employee_id
where login_logs.device_id is not null
group by employees.employee_id, employees.employee_name, employees.department, employees.job_role
having count(distinct login_logs.device_id) > 1
order by device_count desc;

select employees.employee_id, employees.employee_name, employees.department,
login_logs.login_id, login_logs.login_timestamp, login_logs.login_status
from employees join login_logs on login_logs.employee_id = employees.employee_id
where dayofweek(login_logs.login_timestamp) in (1, 7)
or time(login_logs.login_timestamp) < '09:00:00' or time(login_logs.login_timestamp) >= '17:00:00'
order by login_logs.login_timestamp desc;

select devices.employee_id, devices.device_id, devices.device_type, devices.operating_system,
count(*) as failed_attempts from devices
join login_logs on login_logs.device_id = devices.device_id
where lower(login_logs.login_status) = 'failed'
group by devices.employee_id, devices.device_id, devices.device_type, devices.operating_system
order by failed_attempts desc;

select employees.department, count(*) as failed_attempts 
from employees join login_logs
on login_logs.employee_id = employees.employee_id
where lower(login_logs.login_status) = 'failed'
group by employees.department order by failed_attempts desc;

select employees.department,
count(case when lower(login_logs.login_status) = 'failed' then 1 end) as failed_attempts,
count(*) as total_attempts, round( 100.0 * count(case when lower(login_logs.login_status) = 'failed' then 1 end) / count(*), 2) 
as failure_rate_percent
from employees join login_logs on login_logs.employee_id = employees.employee_id
group by employees.department order by failure_rate_percent desc;

select employees.employee_id, employees.department,
count(case when lower(login_logs.login_status) = 'failed' then 1
end) as failed_attempts, count(*) as total_attempts,
round(100.0 * count(case when lower(login_logs.login_status) = 'failed' then 1
end) / count(*), 2) as failure_rate_percent
from employees join login_logs
on login_logs.employee_id = employees.employee_id
group by employees.employee_id, employees.department
having count(*) >= 5
order by failure_rate_percent desc, total_attempts desc;

select devices.device_id, devices.employee_id, devices.device_type, devices.operating_system,
count(case when lower(login_logs.login_status) = 'failed' then 1 end) as failed_attempts,
count(*) as total_attempts, round(100.0 * count(case
when lower(login_logs.login_status) = 'failed' then 1 end) / count(*), 2) as failure_rate_percent
from devices join login_logs on login_logs.device_id = devices.device_id
group by devices.device_id, devices.employee_id, devices.device_type, devices.operating_system
having count(*) >= 5
order by failure_rate_percent desc, total_attempts desc;

create database if not exists cybersecur_investigation;
use cybersecur_investigation;

-- Identifying Data--
describe employees;
describe devices;
describe login_logs;
describe security_alerts;
describe ip_reputation;

-- showing the totals of each colomn---
select count(*) as total_employees from employees;
select count(*) as total_devices from devices;
select count(*) as total_login_logs from login_logs;
select count(*) as total_security_alerts from security_alerts;
select count(*) as total_ip_records from ip_reputation;

-- show tables--
select * from devices;
select * from employees;
select * from security_alerts;
select * from login_logs;
select * from ip_reputation;

-- 1. Count of Security Alerts By Severity--
select severity,
count(*) as total_alerts from security_alerts
group by severity
order by total_alerts desc;

-- 2. Most Frequent Alert Type--
select alert_type,
count(*) as total_alerts from security_alerts
group by alert_type
order by total_alerts desc;

-- 3. Resolved vs Unresolved--
select alert_status,
count(*) as total_alerts from security_alerts
group by alert_status
order by total_alerts desc;

-- 4. Critical and High severity alerts--
select alert_id,
ip_address,
alert_type,
severity,alert_timestamp,
alert_status  from security_alerts
where severity in('Critical','High') and alert_status in('open','investigating')
order by case severity when 'critical' then 1
when 'High' then 2 else 3 end, alert_timestamp;

 -- 5. Calculate security alert resolution time--
select alert_id,
alert_type,
alert_status,
severity,alert_timestamp,
resolved_timestamp,
timestampdiff(minute, alert_timestamp,resolved_timestamp) as resolution_minutes,
round(timestampdiff(minute,alert_timestamp,resolved_timestamp)/60,2) as resolution_hours from security_alerts
where alert_status='Resolved' and resolved_timestamp is not null
order by resolution_minutes desc;

-- 6. Department or time period with highest number of alerts--
select employees.department,
count(security_alerts.alert_id) as total_alerts from security_alerts
join login_logs on security_alerts.ip_address = login_logs.ip_address
join employees on login_logs.employee_id
group by employees.department
order by total_alerts desc;

-- 7. Failed Login Activity over time. --
     -- checking login status--
select login_status,
count(*) as total_attempts from login_logs
group by login_status
order by total_attempts desc;
       -- identify failed login activity by Date--
 select Date(login_timestamp) as login_date,
 count(*) as failed_attempts from login_logs 
 where login_status = 'Failed'
 group by Date(login_timestamp)
 order by Date(login_timestamp) desc;
      -- identify the Addresses for failed login--
select ip_address,
count(*) as failed_attempts from login_logs where login_status = 'Failed'
group by ip_address
order by failed_attempts desc;
   -- Daily changes in login activity
select login_date,
    failed_attempts,
    failed_attempts - lag(failed_attempts)
    over (order by login_date) as daily_change
from (
    select
        date(login_timestamp) as login_date,
        COUNT(*) as failed_attempts
    from login_logs
    where login_status = 'Failed'
    group by date(login_timestamp)
) as daily_totals
order by login_date;

-- 8. Identifying period of failed login Significant increase--
SELECT *
FROM login_logs
WHERE login_status = 'Failed'
AND DATE(login_timestamp) IN (
    '2026-09-14',
    '2026-09-25',
    '2026-09-29')
ORDER BY login_timestamp desc;

create database internship;
use internship;
select * from devices;
select * from employees;
select * from ip_reputation;
select * from login_logs;
select * from security_alerts;

-- A 
-- to rank the employees account by the number of failed login attempts
select
e.employee_id,
e.employee_name,
e.department,
e.employment_status,
SUM(
   case
    when l.login_status = 'Failed' then 1
	else 0
end)
as failed_attempts,

dense_rank() over(
    order by SUM(
        case
        when l.login_status = 'Failed' then 1
        else 0
     end
     ) desc
     ) as failure_rank
     from employees as e
     left join login_logs as l
     on e.employee_id = l.employee_id
     group by 
     e.employee_id,
     e.employee_name,
     e.department,
     e.employment_status
     order by 
     failed_attempts desc;
     
     
     -- B 
     -- Compare each department's failed-login rate with the overall company rate
    with department_stats as (
     select 
		e.department,
		count(l.login_id) as total_attempts,
         
		sum(
	      case
			when l.login_status = 'Failed' then 1
			else 0
			end
			) as failed_attempts
     
            from employees as e
            inner join login_logs as l
            on e.employee_id = l.employee_id
            group by e.department
            ),
            
            company_stats as (
            select
            count(*) as total_attempts,
            
            sum( 
			case
			   when login_status = ' Failed' then 1
               else 0
              end
               ) as failed_attempts
              from login_logs
               )
               
               select 
               d.department,
               d.total_attempts,
               d.failed_attempts,
               
               round( 
                    100.0 * d.failed_attempts /
                    NULLIF(d.total_attempts, 0),
                    2
                    ) as department_failure_rate_pct,
                    
                    round( 
                         100.0 * c.failed_attempts /
                         NULLIF(c.total_attempts, 0),
                         2
                        ) as company_failure_rate_pct,
                         
                   round( 
                         100.0 * d.failed_attempts /
                         NULLIF(d.total_attempts, 0)
                         -
                         100.0 * c.failed_attempts /
                         NULLIF(c.total_attempts, 0),
                         2
                         ) as difference_percentage_points
					
                    from department_stats as d
				cross join company_stats as c
                order by difference_percentage_points desc;
        
        
	-- C 
  -- Compare daily or weekly daily login activity with preceding period
with daily_activity as (
    select
        date(login_timestamp) as activity_date,
        COUNT(*) as total_attempts,
        sum(
            case
                when login_status = 'Failed' then 1
                else 0
            end
        ) as failed_attempts
    from login_logs
    group by date(login_timestamp)
),
activity_comparison as (
    select
        activity_date,
        total_attempts,
        failed_attempts,
        lag(failed_attempts) over (
            order by activity_date
        ) as previous_day_failures,
        lag(total_attempts) over (
            order by activity_date
        ) as previous_day_attempts
   from daily_activity
)
select
    activity_date,
    total_attempts,
    failed_attempts,
    previous_day_failures,
    failed_attempts - previous_day_failures
        as change_in_failed_attempts,
    round(
        100.0 * (failed_attempts - previous_day_failures)
        / NULLIF(previous_day_failures, 0),
        2
    ) as percentage_change
from activity_comparison
order by activity_date;


-- D 
-- create a reusable summary of security activity that management could query regularly
   create or replace view daily_security_summary as 
     select 
     date(login_timestamp) as activity_date,
     count(*) as total_login_attempts,
     sum( 
       case
         when login_status = 'Failed' then 1 
          else 0
         end
       ) as failed_login_attempts,
       
       sum( 
         case 
          when login_status = 'Success' then 1
          else 0
          end
          ) as successfull_login_attempts
          from login_logs
          group by date(login_timestamp);
          
          -- after view has been created we can use 
          select * from daily_security_summary
          order by activity_date;
          
          -- to identify the days with the highest failed login count
          select 
            activity_date,
            failed_login_attempts
            from daily_security_summary
            order by failed_login_attempts desc
            limit 10;
            
            
            -- E 
            -- to know the areas the company should investigate most
            select
            a.alert_id,
            a.employee_id,
            e.employee_name,
            e.department,
            e.employment_status,
            
            a.ip_address,
            ip.risk_level,
            
            a.alert_type,
            a.severity,
            a.alert_status,
            a.alert_timestamp
            
            from security_alerts as a
            left join employees as e
            on a.employee_id = e.employee_id
            
            left join ip_reputation as ip
            on a.ip_address = ip.ip_address
            where a.alert_status in ('Open', 'Investigating')
            and (
               a.severity in ('High', 'Critical')
               or ip.risk_level = 'High Risk'
               or e.employment_status = 'Inactive'
               )
               order by
               case
                 when a.severity = 'Critical' then 1
                 when a.severity = 'High' then 2
                 else 3
                 end,
                 a.alert_timestamp desc;



/* ============================================================
   BUSINESS INSIGHTS & RECOMMENDATIONS (5 KEY INSIGHTS)
   Cybersecurity Login and Security Analysis
   ============================================================

   1. LOGIN FAILURE PATTERNS AND EMPLOYEE ACCOUNTS
   BUSINESS INSIGHT:
   Repeated failed login attempts, especially when followed by a
   successful login, may indicate password difficulties or
   potentially suspicious account activity.
   BUSINESS IMPLICATION:
   Accounts with unusual failure patterns may be exposed to
   password guessing or credential compromise.
   BUSINESS RECOMMENDATION:
   Investigate accounts with repeated failures, verify legitimate
   user activity, and strengthen authentication where necessary.

   2. HIGH-RISK IP ADDRESSES AND SUCCESSFUL LOGINS
   BUSINESS INSIGHT:
   Login activity from high-risk IP addresses, particularly
   successful logins, deserves priority security review.
   BUSINESS IMPLICATION:
   Such activity may indicate compromised credentials or
   unauthorized access, although IP reputation alone is not proof.
   BUSINESS RECOMMENDATION:
   Review the associated account, IP reputation, and login history;
   apply protective controls when suspicious activity is confirmed.

   3. DEPARTMENTAL AND DEVICE LOGIN FAILURE RATES
   BUSINESS INSIGHT:
   Comparing failure rates across departments, employees, and
   devices helps identify where authentication problems are
   concentrated relative to login volume.
   BUSINESS IMPLICATION:
   Elevated rates may reflect user difficulties, device issues,
   or suspicious activity—not necessarily an attack.
   BUSINESS RECOMMENDATION:
   Investigate high-rate departments and devices, provide targeted
   support or awareness training, and improve monitoring.

   4. AFTER-HOURS AND MULTIPLE-DEVICE ACCESS
   BUSINESS INSIGHT:
   Login activity outside normal working hours and access through
   multiple devices reveal employee access patterns.
   BUSINESS IMPLICATION:
   These patterns can be legitimate, but unexpected activity may
   indicate account sharing or unauthorized access.
   BUSINESS RECOMMENDATION:
   Verify unusual access against employee schedules and approved
   devices, and enforce appropriate device and authentication
   policies.

   5. SECURITY ALERT PRIORITIZATION AND RESPONSE
   BUSINESS INSIGHT:
   Alert severity, status, type, and resolution time help assess
   incident priorities and response progress.
   BUSINESS IMPLICATION:
   Unresolved high/critical alerts and long resolution times may
   increase organizational exposure and indicate response delays.
   BUSINESS RECOMMENDATION:
   Prioritize critical and high alerts, assign investigations,
   monitor resolution time, and review recurring alert categories
   to strengthen preventive controls.

   ============================================================
   END OF 5 BUSINESS INSIGHTS
   ============================================================ */
