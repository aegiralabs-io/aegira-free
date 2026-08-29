use serde::Deserialize;
use std::collections::{HashMap,HashSet};
use std::fs::{self,File,OpenOptions};
use std::io::{BufRead,BufReader,Seek,SeekFrom,Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path,PathBuf};
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration,Instant};

const LOGS_DIR:&str="/var/log/aegira";
const LOG_FILE_PATH:&str="/var/log/aegira/system.log";
const INCIDENT_LOG_PATH:&str="/var/log/aegira/incident.log";

const SYSTEM_BUILTIN_RULES_DIR:&str="/etc/aegira/rules/builtin";
const SYSTEM_CUSTOM_RULES_DIR:&str="/etc/aegira/rules/custom";

const POLL_INTERVAL_SECS:u64=2;
const RULE_RELOAD_INTERVAL_SECS:u64=10;
const COMMAND_TIMEOUT_SECS:u64=20;
const VERIFY_DELAY_SECS:u64=2;
const MAX_VERIFY_ATTEMPTS:u32=5;

const INCIDENT_COOLDOWN_SECS:u64=30;
const MAX_INCIDENT_LOG_BYTES:u64=10*1024*1024;

const SELF_SERVICE:&str="aegira";
const MIN_MATCH_SCORE:i32=60;

#[derive(Debug,Deserialize,Clone)]
struct Rule{
    id:String,
    name:String,

    #[serde(default)]
    severity:String,

    #[serde(default)]
    error_patterns:Vec<String>,

    #[serde(default)]
    context_patterns:Vec<String>,

    remediation:Remediation,
    verification:Verification,

    #[serde(default)]
    priority:i32,
}

#[derive(Debug,Deserialize,Clone)]
#[serde(tag="type")]
enum Remediation{
    #[serde(rename="service_restart")]
    ServiceRestart{service:String},

    #[serde(rename="container_restart")]
    ContainerRestart{container:String},
}

#[derive(Debug,Deserialize,Clone)]
#[serde(tag="type")]
enum Verification{
    #[serde(rename="service_active")]
    ServiceActive{service:String},

    #[serde(rename="container_running")]
    ContainerRunning{container:String},
}

/* ============================================================
   PATHS
============================================================ */

fn project_root()->Option<PathBuf>{
    let cwd=std::env::current_dir().ok()?;

    if cwd.join("rules").exists(){
        Some(cwd)
    }else{
        None
    }
}

fn project_builtin_rules_dir()->Option<PathBuf>{
    project_root().map(|root|root.join("rules").join("builtin"))
}

fn project_custom_rules_dir()->Option<PathBuf>{
    project_root().map(|root|root.join("rules").join("custom"))
}

/* ============================================================
   ENVIRONMENT SETUP
============================================================ */

fn ensure_file(path:&Path)->Result<(),String>{
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_|())
        .map_err(|e|format!("Failed to create {}: {}",path.display(),e))
}

fn ensure_environment_setup()->Result<(),String>{
    fs::create_dir_all(LOGS_DIR)
        .map_err(|e|format!("Failed to create {}: {}",LOGS_DIR,e))?;

    fs::create_dir_all(SYSTEM_BUILTIN_RULES_DIR)
        .map_err(|e|format!("Failed to create {}: {}",SYSTEM_BUILTIN_RULES_DIR,e))?;

    fs::create_dir_all(SYSTEM_CUSTOM_RULES_DIR)
        .map_err(|e|format!("Failed to create {}: {}",SYSTEM_CUSTOM_RULES_DIR,e))?;

    ensure_file(Path::new(LOG_FILE_PATH))?;
    ensure_file(Path::new(INCIDENT_LOG_PATH))?;

    Ok(())
}

/* ============================================================
   INCIDENT LOGGING
============================================================ */

fn rotate_incident_log_if_needed(){
    let path=Path::new(INCIDENT_LOG_PATH);

    let size=match fs::metadata(path){
        Ok(metadata)=>metadata.len(),
        Err(_)=>return,
    };

    if size<MAX_INCIDENT_LOG_BYTES{
        return;
    }

    let rotated=Path::new(LOGS_DIR).join("incident.log.1");

    let _=fs::remove_file(&rotated);

    if let Err(e)=fs::rename(path,&rotated){
        eprintln!(
            "[LOG ERROR] Failed to rotate incident log: {}",
            e
        );
    }
}

fn log_incident(msg:&str){
    println!("{}",msg);

    rotate_incident_log_if_needed();

    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(INCIDENT_LOG_PATH)
    {
        Ok(mut file)=>{
            let _=writeln!(file,"{}",msg);
        }

        Err(e)=>{
            eprintln!(
                "[LOG ERROR] Failed to write incident log: {}",
                e
            );
        }
    }
}

/* ============================================================
   RULE VALIDATION
============================================================ */

fn non_empty(value:&str)->bool{
    !value.trim().is_empty()
}

fn normalize_service_name(service:&str)->String{
    service
        .trim()
        .trim_end_matches(".service")
        .to_lowercase()
}

fn validate_rule(rule:&Rule)->Result<(),String>{
    if !non_empty(&rule.id){
        return Err("Rule id cannot be empty".to_string());
    }

    if !non_empty(&rule.name){
        return Err(format!(
            "Rule '{}' has an empty name",
            rule.id
        ));
    }

    if rule.error_patterns.is_empty(){
        return Err(format!(
            "Rule '{}' must contain at least one error pattern",
            rule.id
        ));
    }

    for pattern in &rule.error_patterns{
        if !non_empty(pattern){
            return Err(format!(
                "Rule '{}' contains an empty error pattern",
                rule.id
            ));
        }
    }

    for pattern in &rule.context_patterns{
        if !non_empty(pattern){
            return Err(format!(
                "Rule '{}' contains an empty context pattern",
                rule.id
            ));
        }
    }

    match &rule.remediation{
        Remediation::ServiceRestart{service}=>{
            if !non_empty(service){
                return Err(format!(
                    "Rule '{}' has an empty remediation service",
                    rule.id
                ));
            }

            if is_aegira_service(service){
                return Err(format!(
                    "Rule '{}' attempts to restart Aegira itself",
                    rule.id
                ));
            }
        }

        Remediation::ContainerRestart{container}=>{
            if !non_empty(container){
                return Err(format!(
                    "Rule '{}' has an empty remediation container",
                    rule.id
                ));
            }
        }
    }

    match &rule.verification{
        Verification::ServiceActive{service}=>{
            if !non_empty(service){
                return Err(format!(
                    "Rule '{}' has an empty verification service",
                    rule.id
                ));
            }
        }

        Verification::ContainerRunning{container}=>{
            if !non_empty(container){
                return Err(format!(
                    "Rule '{}' has an empty verification container",
                    rule.id
                ));
            }
        }
    }

    Ok(())
}

fn is_aegira_service(service:&str)->bool{
    normalize_service_name(service)==SELF_SERVICE
}

/* ============================================================
   RULE PARSING
============================================================ */

fn parse_rules(contents:&str)->Result<Vec<Rule>,String>{
    let trimmed=contents.trim();

    if trimmed.is_empty(){
        return Ok(Vec::new());
    }

    if trimmed.starts_with('['){
        serde_json::from_str::<Vec<Rule>>(trimmed)
            .map_err(|e|e.to_string())
    }else{
        serde_json::from_str::<Rule>(trimmed)
            .map(|rule|vec![rule])
            .map_err(|e|e.to_string())
    }
}

struct RuleLoadResult{
    rules:Vec<Rule>,
    json_files_found:usize,
    parse_errors:usize,
}

fn empty_rule_load_result()->RuleLoadResult{
    RuleLoadResult{
        rules:Vec::new(),
        json_files_found:0,
        parse_errors:0,
    }
}

fn load_rules_from_directory(path:&Path)->RuleLoadResult{
    let mut result=empty_rule_load_result();

    if !path.exists(){
        return result;
    }

    let entries=match fs::read_dir(path){
        Ok(entries)=>entries,

        Err(e)=>{
            log_incident(&format!(
                "[RULES ERROR] Failed to read {}: {}",
                path.display(),
                e
            ));

            result.parse_errors+=1;
            return result;
        }
    };

    let mut files:Vec<PathBuf>=entries
        .flatten()
        .map(|entry|entry.path())
        .filter(|path|{
            path.extension()
                .and_then(|value|value.to_str())
                ==Some("json")
        })
        .collect();

    files.sort();

    for file_path in files{
        result.json_files_found+=1;

        let contents=match fs::read_to_string(&file_path){
            Ok(contents)=>contents,

            Err(e)=>{
                result.parse_errors+=1;

                log_incident(&format!(
                    "[RULES ERROR] Failed reading {}: {}",
                    file_path.display(),
                    e
                ));

                continue;
            }
        };

        let parsed=match parse_rules(&contents){
            Ok(rules)=>rules,

            Err(e)=>{
                result.parse_errors+=1;

                log_incident(&format!(
                    "[RULES ERROR] Invalid JSON {}: {}",
                    file_path.display(),
                    e
                ));

                continue;
            }
        };

        for rule in parsed{
            match validate_rule(&rule){
                Ok(())=>{
                    result.rules.push(rule);
                }

                Err(e)=>{
                    result.parse_errors+=1;

                    log_incident(&format!(
                        "[RULES ERROR] Invalid rule in {}: {}",
                        file_path.display(),
                        e
                    ));
                }
            }
        }
    }

    result
}

/* ============================================================
   DEFAULT FALLBACK
============================================================ */

fn get_hardcoded_default_rules()->Vec<Rule>{
    vec![
        Rule{
            id:"connection_refused".to_string(),
            name:"Connection Refused".to_string(),
            severity:"high".to_string(),
            error_patterns:vec![
                "connection refused".to_string()
            ],
            context_patterns:Vec::new(),
            remediation:Remediation::ServiceRestart{
                service:"cron".to_string()
            },
            verification:Verification::ServiceActive{
                service:"cron".to_string()
            },
            priority:10,
        }
    ]
}

/* ============================================================
   RULE LOADING
============================================================ */

fn merge_rules(
    destination:&mut Vec<Rule>,
    seen_ids:&mut HashSet<String>,
    incoming:Vec<Rule>,
    source:&Path
){
    for rule in incoming{
        let normalized_id=rule.id.trim().to_lowercase();

        if !seen_ids.insert(normalized_id){
            log_incident(&format!(
                "[RULES ERROR] Duplicate rule ID '{}' ignored from {}",
                rule.id,
                source.display()
            ));

            continue;
        }

        log_incident(&format!(
            "[RULES] Loaded: {}",
            rule.id
        ));

        destination.push(rule);
    }
}

fn load_all_rules()->Vec<Rule>{
    log_incident("[RULES] Loading built-in rules...");

    let mut rules=Vec::new();
    let mut seen_ids=HashSet::new();

    let mut total_json_files=0usize;
    let mut total_errors=0usize;

    let mut sources:Vec<PathBuf>=Vec::new();

    if let Some(project_dir)=project_builtin_rules_dir(){
        sources.push(project_dir);
    }

    sources.push(
        PathBuf::from(SYSTEM_BUILTIN_RULES_DIR)
    );

    for source in sources{
        let result=load_rules_from_directory(&source);

        total_json_files+=result.json_files_found;
        total_errors+=result.parse_errors;

        merge_rules(
            &mut rules,
            &mut seen_ids,
            result.rules,
            &source
        );
    }

    if total_json_files==0{
        log_incident(
            "[RULES] No built-in JSON rules found. Loading bootstrap fallback rule."
        );

        for rule in get_hardcoded_default_rules(){
            seen_ids.insert(
                rule.id.trim().to_lowercase()
            );

            log_incident(&format!(
                "[RULES] Loaded fallback: {}",
                rule.id
            ));

            rules.push(rule);
        }
    }else if rules.is_empty()&&total_errors>0{
        log_incident(
            "[RULES ERROR] Built-in rule files exist but none are valid."
        );
    }

    if let Some(custom_dir)=project_custom_rules_dir(){
        if custom_dir.exists(){
            let custom=load_rules_from_directory(&custom_dir);

            if custom.json_files_found>0{
                log_incident(
                    "[UPGRADE REQUIRED] Custom rules are not available in Aegira Free."
                );
            }
        }
    }

    let system_custom=Path::new(SYSTEM_CUSTOM_RULES_DIR);

    if system_custom.exists(){
        let custom=load_rules_from_directory(system_custom);

        if custom.json_files_found>0{
            log_incident(
                "[UPGRADE REQUIRED] Custom rules are not available in Aegira Free."
            );
        }
    }

    rules.sort_by(|a,b|{
        a.id.to_lowercase()
            .cmp(&b.id.to_lowercase())
    });

    log_incident(&format!(
        "[RULES] Active built-in rules: {}",
        rules.len()
    ));

    rules
}

/* ============================================================
   MATCHING ENGINE
============================================================ */

fn contains_case_insensitive(
    text:&str,
    pattern:&str
)->bool{
    text.to_lowercase()
        .contains(&pattern.to_lowercase())
}

fn calculate_match_score(
    rule:&Rule,
    incident:&str
)->Option<i32>{
    let mut error_matches:usize=0;
    let mut context_matches=0;

    for pattern in &rule.error_patterns{
        if contains_case_insensitive(incident,pattern){
            error_matches+=1;
        }
    }

    if error_matches==0{
        return None;
    }

    for pattern in &rule.context_patterns{
        if contains_case_insensitive(incident,pattern){
            context_matches+=1;
        }
    }

    let error_score=60+(error_matches.saturating_sub(1)*10);
    let context_score=context_matches*10;
    let priority_score=rule.priority.clamp(-20,20);

    Some(
        (error_score+context_score+priority_score)
            .clamp(0,100)
    )
}

fn find_best_rule<'a>(
    rules:&'a [Rule],
    incident:&str
)->Option<(&'a Rule,i32)>{
    let mut best:Option<(&Rule,i32)>=None;

    for rule in rules{
        let score=match calculate_match_score(rule,incident){
            Some(score)=>score,
            None=>continue,
        };

        if score<MIN_MATCH_SCORE{
            continue;
        }

        match best{
            None=>{
                best=Some((rule,score));
            }

            Some((current_rule,current_score))=>{
                if score>current_score
                    ||(
                        score==current_score
                        &&rule.id
                            .to_lowercase()
                            <current_rule.id.to_lowercase()
                    )
                {
                    best=Some((rule,score));
                }
            }
        }
    }

    best
}

/* ============================================================
   BINARY RESOLUTION
============================================================ */

fn find_binary<'a>(
    candidates:&'a [&'a str]
)->Result<&'a str,String>{
    for candidate in candidates{
        if Path::new(candidate).exists(){
            return Ok(candidate);
        }
    }

    Err(format!(
        "Required binary not found. Checked: {}",
        candidates.join(", ")
    ))
}

fn systemctl_binary()->Result<&'static str,String>{
    find_binary(&[
        "/usr/bin/systemctl",
        "/bin/systemctl",
    ])
}

fn docker_binary()->Result<&'static str,String>{
    find_binary(&[
        "/usr/bin/docker",
        "/bin/docker",
        "/usr/local/bin/docker",
    ])
}

/* ============================================================
   COMMAND EXECUTION
============================================================ */

fn execute_command(
    executable:&str,
    args:&[&str]
)->Result<(),String>{
    log_incident(&format!(
        "[EXEC] {} {}",
        executable,
        args.join(" ")
    ));

    let mut child=Command::new(executable)
        .args(args)
        .spawn()
        .map_err(|e|format!(
            "Failed to start {}: {}",
            executable,
            e
        ))?;

    let start=Instant::now();

    loop{
        match child.try_wait(){
            Ok(Some(status))=>{
                if status.success(){
                    return Ok(());
                }

                return Err(format!(
                    "{} exited with status {}",
                    executable,
                    status
                ));
            }

            Ok(None)=>{
                if start.elapsed()
                    >=Duration::from_secs(
                        COMMAND_TIMEOUT_SECS
                    )
                {
                    let _=child.kill();
                    let _=child.wait();

                    return Err(format!(
                        "{} timed out after {} seconds",
                        executable,
                        COMMAND_TIMEOUT_SECS
                    ));
                }

                sleep(
                    Duration::from_millis(100)
                );
            }

            Err(e)=>{
                return Err(format!(
                    "Failed waiting for {}: {}",
                    executable,
                    e
                ));
            }
        }
    }
}

/* ============================================================
   REMEDIATION
============================================================ */

fn perform_remediation(
    remediation:&Remediation
)->Result<(),String>{
    match remediation{
        Remediation::ServiceRestart{service}=>{
            if is_aegira_service(service){
                return Err(
                    "Refusing remediation: rule attempts to restart Aegira itself"
                    .to_string()
                );
            }

            let systemctl=systemctl_binary()?;

            log_incident(&format!(
                "[RECOVERY] Restarting service: {}",
                service
            ));

            execute_command(
                systemctl,
                &["restart",service.trim()]
            )
        }

        Remediation::ContainerRestart{container}=>{
            let docker=docker_binary()?;

            log_incident(&format!(
                "[RECOVERY] Restarting container: {}",
                container
            ));

            execute_command(
                docker,
                &["restart",container.trim()]
            )
        }
    }
}

/* ============================================================
   VERIFICATION
============================================================ */

fn verify_recovery(
    verification:&Verification
)->bool{
    match verification{
        Verification::ServiceActive{service}=>{
            let systemctl=match systemctl_binary(){
                Ok(path)=>path,

                Err(e)=>{
                    log_incident(&format!(
                        "[VERIFY ERROR] {}",
                        e
                    ));

                    return false;
                }
            };

            log_incident(&format!(
                "[VERIFY] Checking service: {}",
                service
            ));

            match Command::new(systemctl)
                .args(["is-active",service.trim()])
                .output()
            {
                Ok(output)=>{
                    let active=
                        output.status.success()
                        &&String::from_utf8_lossy(
                            &output.stdout
                        )
                        .trim()=="active";

                    if active{
                        log_incident(
                            "[VERIFY] Service is active"
                        );
                    }else{
                        log_incident(
                            "[VERIFY] Service is NOT active"
                        );
                    }

                    active
                }

                Err(e)=>{
                    log_incident(&format!(
                        "[VERIFY ERROR] {}",
                        e
                    ));

                    false
                }
            }
        }

        Verification::ContainerRunning{container}=>{
            let docker=match docker_binary(){
                Ok(path)=>path,

                Err(e)=>{
                    log_incident(&format!(
                        "[VERIFY ERROR] {}",
                        e
                    ));

                    return false;
                }
            };

            log_incident(&format!(
                "[VERIFY] Checking container: {}",
                container
            ));

            match Command::new(docker)
                .args([
                    "inspect",
                    "-f",
                    "{{.State.Running}}",
                    container.trim()
                ])
                .output()
            {
                Ok(output)=>{
                    let running=
                        output.status.success()
                        &&String::from_utf8_lossy(
                            &output.stdout
                        )
                        .trim()=="true";

                    if running{
                        log_incident(
                            "[VERIFY] Container is running"
                        );
                    }else{
                        log_incident(
                            "[VERIFY] Container is NOT running"
                        );
                    }

                    running
                }

                Err(e)=>{
                    log_incident(&format!(
                        "[VERIFY ERROR] {}",
                        e
                    ));

                    false
                }
            }
        }
    }
}

/* ============================================================
   RECOVERY
============================================================ */

fn recover_with_rule(
    rule:&Rule
)->Result<(),String>{
    log_incident(&format!(
        "[MATCH] Rule: {}",
        rule.name
    ));

    log_incident(&format!(
        "[MATCH] Rule ID: {}",
        rule.id
    ));

    if !rule.severity.trim().is_empty(){
        log_incident(&format!(
            "[MATCH] Severity: {}",
            rule.severity
        ));
    }

    perform_remediation(
        &rule.remediation
    )?;

    sleep(
        Duration::from_secs(
            VERIFY_DELAY_SECS
        )
    );

    for attempt in 1..=MAX_VERIFY_ATTEMPTS{
        log_incident(&format!(
            "[VERIFY] Verification attempt {}/{}",
            attempt,
            MAX_VERIFY_ATTEMPTS
        ));

        if verify_recovery(
            &rule.verification
        ){
            return Ok(());
        }

        if attempt<MAX_VERIFY_ATTEMPTS{
            sleep(
                Duration::from_secs(
                    VERIFY_DELAY_SECS
                )
            );
        }
    }

    Err(
        "Remediation executed but health verification failed"
        .to_string()
    )
}

/* ============================================================
   INCIDENT COOLDOWN
============================================================ */

fn incident_key(
    rule:&Rule,
    incident:&str
)->String{
    format!(
        "{}:{}",
        rule.id.to_lowercase(),
        incident.to_lowercase()
    )
}

fn cleanup_cooldowns(
    cooldowns:&mut HashMap<String,Instant>
){
    let duration=
        Duration::from_secs(
            INCIDENT_COOLDOWN_SECS
        );

    cooldowns.retain(
        |_,time|time.elapsed()<duration
    );
}

/* ============================================================
   INCIDENT PROCESSING
============================================================ */

fn process_incident(
    rules:&[Rule],
    incident:&str,
    cooldowns:&mut HashMap<String,Instant>
){
    cleanup_cooldowns(cooldowns);

    let start=Instant::now();

    log_incident(&format!(
        "[WATCHER] Incident detected: {}",
        incident
    ));

    log_incident(
        "================ INCIDENT ================"
    );

    log_incident(incident);

    let (rule,score)=match find_best_rule(
        rules,
        incident
    ){
        Some(result)=>result,

        None=>{
            log_incident(
                "[MATCH] No known remediation rule found"
            );

            log_incident(
                "[MANUAL ACTION] Unknown incident requires investigation"
            );

            return;
        }
    };

    let key=incident_key(rule,incident);

    if cooldowns.contains_key(&key){
        log_incident(&format!(
            "[COOLDOWN] Duplicate incident skipped for rule '{}'",
            rule.id
        ));

        return;
    }

    cooldowns.insert(
        key,
        Instant::now()
    );

    log_incident(&format!(
        "[MATCH] Confidence score: {}",
        score
    ));

    match recover_with_rule(rule){
        Ok(())=>{
            log_incident(&format!(
                "[RESOLVED] Incident automatically recovered in {:.2?}",
                start.elapsed()
            ));
        }

        Err(e)=>{
            log_incident(&format!(
                "[RECOVERY FAILED] {}",
                e
            ));

            log_incident(&format!(
                "[MANUAL ACTION] Rule '{}' requires intervention",
                rule.id
            ));
        }
    }
}

/* ============================================================
   FILE IDENTITY
============================================================ */

#[derive(Clone,Copy,PartialEq,Eq)]
struct FileIdentity{
    dev:u64,
    ino:u64,
}

fn file_identity(
    path:&Path
)->Result<FileIdentity,String>{
    let metadata=fs::metadata(path)
        .map_err(|e|format!(
            "Failed to read metadata for {}: {}",
            path.display(),
            e
        ))?;

    Ok(
        FileIdentity{
            dev:metadata.dev(),
            ino:metadata.ino(),
        }
    )
}

/* ============================================================
   RULE RELOAD
============================================================ */

fn should_reload_rules(
    last_reload:&Instant
)->bool{
    last_reload.elapsed()
        >=Duration::from_secs(
            RULE_RELOAD_INTERVAL_SECS
        )
}

/* ============================================================
   LOG TAILING
============================================================ */

fn ensure_monitored_log_exists(){
    if !Path::new(LOG_FILE_PATH).exists(){
        if let Err(e)=ensure_file(
            Path::new(LOG_FILE_PATH)
        ){
            eprintln!(
                "[LOG ERROR] Failed recreating monitored log: {}",
                e
            );
        }else{
            log_incident(
                "[INFO] Monitored log recreated"
            );
        }
    }
}

fn main(){
    if let Err(e)=ensure_environment_setup(){
        eprintln!(
            "[FATAL] Environment setup failed: {}",
            e
        );

        return;
    }

    log_incident(
        "[INFO] Aegira Free Recovery Engine Started"
    );

    log_incident(
        "[INFO] Mode: FREE"
    );

    log_incident(&format!(
        "[INFO] Monitoring log: {}",
        LOG_FILE_PATH
    ));

    let mut rules=load_all_rules();
    let mut last_rule_reload=Instant::now();

    if rules.is_empty(){
        log_incident(
            "[WARNING] No valid remediation rules loaded"
        );
    }else{
        log_incident(&format!(
            "[INFO] {} remediation rules ready",
            rules.len()
        ));
    }

    ensure_monitored_log_exists();

    let mut position=match fs::metadata(LOG_FILE_PATH){
        Ok(metadata)=>metadata.len(),

        Err(e)=>{
            log_incident(&format!(
                "[FATAL] Failed to inspect monitored log: {}",
                e
            ));

            return;
        }
    };

    let mut identity=match file_identity(
        Path::new(LOG_FILE_PATH)
    ){
        Ok(identity)=>identity,

        Err(e)=>{
            log_incident(&format!(
                "[FATAL] {}",
                e
            ));

            return;
        }
    };

    let mut partial_line=String::new();

    let mut cooldowns:HashMap<String,Instant>=
        HashMap::new();

    log_incident(
        "[INFO] Monitoring new log entries..."
    );

    loop{
        if should_reload_rules(
            &last_rule_reload
        ){
            rules=load_all_rules();

            last_rule_reload=Instant::now();

            log_incident(&format!(
                "[RULES] Reload complete. Active rules: {}",
                rules.len()
            ));
        }

        ensure_monitored_log_exists();

        let metadata=match fs::metadata(
            LOG_FILE_PATH
        ){
            Ok(metadata)=>metadata,

            Err(e)=>{
                log_incident(&format!(
                    "[LOG ERROR] Failed to stat monitored log: {}",
                    e
                ));

                sleep(
                    Duration::from_secs(
                        POLL_INTERVAL_SECS
                    )
                );

                continue;
            }
        };

        let new_identity=FileIdentity{
            dev:metadata.dev(),
            ino:metadata.ino(),
        };

        let file_size=metadata.len();

        if new_identity!=identity{
            log_incident(
                "[INFO] Log file replacement detected. Resetting position."
            );

            identity=new_identity;
            position=0;
            partial_line.clear();
        }else if file_size<position{
            log_incident(
                "[INFO] Log truncation detected. Resetting position."
            );

            position=0;
            partial_line.clear();
        }

        if file_size<=position{
            sleep(
                Duration::from_secs(
                    POLL_INTERVAL_SECS
                )
            );

            continue;
        }

        let file=match File::open(
            LOG_FILE_PATH
        ){
            Ok(file)=>file,

            Err(e)=>{
                log_incident(&format!(
                    "[LOG ERROR] Failed opening monitored log: {}",
                    e
                ));

                sleep(
                    Duration::from_secs(
                        POLL_INTERVAL_SECS
                    )
                );

                continue;
            }
        };

        let mut reader=BufReader::new(file);

        if let Err(e)=reader.seek(
            SeekFrom::Start(position)
        ){
            log_incident(&format!(
                "[LOG ERROR] Failed seeking monitored log: {}",
                e
            ));

            sleep(
                Duration::from_secs(
                    POLL_INTERVAL_SECS
                )
            );

            continue;
        }

        loop{
            let mut line=String::new();

            let bytes_read=match reader.read_line(
                &mut line
            ){
                Ok(bytes)=>bytes,

                Err(e)=>{
                    log_incident(&format!(
                        "[LOG ERROR] Failed reading monitored log: {}",
                        e
                    ));

                    break;
                }
            };

            if bytes_read==0{
                break;
            }

            position+=bytes_read as u64;

            partial_line.push_str(&line);

            if !partial_line.ends_with('\n'){
                continue;
            }

            let incident=
                partial_line
                    .trim()
                    .to_string();

            partial_line.clear();

            if incident.contains("[ERROR]")
                ||incident.contains("[CRITICAL]")
            {
                process_incident(
                    &rules,
                    &incident,
                    &mut cooldowns
                );
            }
        }

        sleep(
            Duration::from_secs(
                POLL_INTERVAL_SECS
            )
        );
    }
}
