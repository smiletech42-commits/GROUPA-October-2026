# GROUP A
Adisa Taiwo Question E
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
