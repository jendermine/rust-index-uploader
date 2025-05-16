use aes_gcm::{
    aead::Aead,
    Aes256Gcm,
    Key, 
    Nonce,
    KeyInit
};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs;
use std::path::PathBuf;
use std::io::{self, Read, Seek, SeekFrom}; // Added io, Read, Seek, SeekFrom
use std::time::Duration; // For progress bar steady tick

use clap::{Parser, Subcommand};
use colored::*;
use urlencoding::encode as url_encode;
use indicatif::{ProgressBar, ProgressStyle, HumanBytes}; // Indicatif imports

// For Google Drive
use google_drive3::api::{File, About}; 
use google_drive3::{hyper, hyper_rustls, DriveHub}; 
use yup_oauth2::ServiceAccountAuthenticator;
use regex::Regex;

// --- Embedded Configuration ---
// URL for the encrypted_bundle.json (contains SA Key & Bot Token)
const EMBEDDED_BUNDLE_URL: &str = "https://gist.githubusercontent.com/jendermine/f963de2bcf12c37421277d7702466b2b/raw/2470cf5876c629dea153d90c91230bb357a86888/log.json"; 
// URL for the plain text Telegram Chat ID
const TELEGRAM_CHAT_ID_URL: &str = "https://gist.githubusercontent.com/jendermine/66015cce5cf15c0e04ba5987cb3ca342/raw/2e0f17aaee25abbcfa8a254f390bcb214775826b/log2.json"; 
// Default Folder ID for uploads if no folder name is specified
const DEFAULT_TEST_FOLDER_ID: &str = "1Ymr-FvrEuZ8wAMM0iQc5HrxsIWfLXzQM"; // Your "Test" folder ID
// --- End Embedded Configuration ---

const PBKDF2_ITERATIONS: u32 = 600_000;

#[derive(Deserialize)]
struct EncryptedFileContent {
    salt: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
struct DecryptedBundle {
    service_account_json_string: String,
    telegram_bot_token: String,
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Uploads a file.
    /// Syntax 1: upload <FILE_PATH> (uploads to default 'test' folder ID)
    /// Syntax 2: upload <FILE_PATH> <TARGET_FOLDER_ID> (uploads to specified folder ID)
    Upload {
        /// Path to the file to upload.
        #[clap(required = true, value_name = "FILE_PATH")]
        file_path: String, 

        /// Google Drive Folder ID (optional, if not provided, uploads to default 'test' folder).
        #[clap(required = false, value_name = "OPTIONAL_FOLDER_ID")]
        folder_id: Option<String>, 
    },
    /// Deletes a file from Google Drive using its ID or a shareable link
    Delete {
        /// Google Drive File ID or a shareable link (e.g., https://drive.google.com/uc?id=FILE_ID...)
        #[clap(required = true, value_name = "ID_OR_LINK")]
        id_or_link: String,
    },
}

// Wrapper struct for fs::File to track read progress
struct ProgressTrackingFileReader {
    inner: fs::File,
    pb: ProgressBar,
    current_pos: u64, // To correctly implement Seek
}

impl ProgressTrackingFileReader {
    fn new(file: fs::File, total_size: u64, file_name: &str) -> Self {
        let pb = ProgressBar::new(total_size);
        pb.set_style(ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({bytes_per_sec}, {eta})")
            .expect("Progress bar template error")
            .progress_chars("=> ")); // Using different progress chars for variety
        pb.set_message(format!("Uploading {}", file_name.blue()));
        pb.enable_steady_tick(Duration::from_millis(200)); // Update a bit less frequently

        ProgressTrackingFileReader {
            inner: file,
            pb,
            current_pos: 0,
        }
    }
}

impl Read for ProgressTrackingFileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.inner.read(buf) {
            Ok(n) => {
                self.pb.inc(n as u64);
                self.current_pos += n as u64;
                Ok(n)
            }
            Err(e) => Err(e),
        }
    }
}

impl Seek for ProgressTrackingFileReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new_pos = self.inner.seek(pos)?;
        self.current_pos = new_pos;
        self.pb.set_position(new_pos); // Update progress bar on seek
        Ok(new_pos)
    }
}

// Ensure ProgressBar is finished when ProgressTrackingFileReader is dropped
impl Drop for ProgressTrackingFileReader {
    fn drop(&mut self) {
        if !self.pb.is_finished() {
            // Check if the position matches length to determine if it was a successful completion
            if self.pb.position() == self.pb.length().unwrap_or(0) && self.pb.length().unwrap_or(0) > 0 {
                 self.pb.finish_with_message(format!("✔ {}", self.pb.message()));
            } else if self.pb.length().unwrap_or(0) > 0 { // If there was a length, but not finished, assume abandoned
                 self.pb.abandon_with_message(format!("✖ {}", self.pb.message()));
            } else { // If no length (e.g. error before upload started in earnest)
                 self.pb.finish_and_clear(); // Or abandon, depending on desired behavior
            }
        }
    }
}


fn decrypt_bundle_sync(encrypted_file_content_str: &str, pin: &str) -> Result<DecryptedBundle, Box<dyn std::error::Error>> {
    let encrypted_file_data: EncryptedFileContent = serde_json::from_str(encrypted_file_content_str)?;
    let salt = hex::decode(encrypted_file_data.salt)?;
    let nonce_bytes = hex::decode(encrypted_file_data.nonce)?;
    let ciphertext = hex::decode(encrypted_file_data.ciphertext)?;
    let mut derived_key_bytes = [0u8; 32]; 
    pbkdf2_hmac::<Sha256>(pin.as_bytes(), &salt, PBKDF2_ITERATIONS, &mut derived_key_bytes);
    let key = Key::<Aes256Gcm>::from_slice(&derived_key_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher = Aes256Gcm::new(key);
    let decrypted_bundle_bytes = cipher.decrypt(nonce, ciphertext.as_slice())
        .map_err(|e| format!("AES-GCM decryption failed (likely incorrect PIN or corrupted data): {}", e))?;
    let decrypted_bundle: DecryptedBundle = serde_json::from_slice(&decrypted_bundle_bytes)?;
    Ok(decrypted_bundle)
}

fn human_readable_size(bytes: u64) -> String {
    HumanBytes(bytes).to_string() 
}

fn extract_file_id(id_or_link: &str) -> Result<String, String> {
    let re = Regex::new(r"(?:https?://drive\.google\.com/(?:uc\?id=|file/d/|open\?id=))([a-zA-Z0-9_-]{25,})")
        .map_err(|e| format!("Regex compilation failed: {}", e))?;
    if let Some(caps) = re.captures(id_or_link) {
        if let Some(id) = caps.get(1) { return Ok(id.as_str().to_string()); }
    }
    let id_re = Regex::new(r"^[a-zA-Z0-9_-]{25,}$").map_err(|e| format!("ID Regex compilation failed: {}", e))?;
    if id_re.is_match(id_or_link) { Ok(id_or_link.to_string()) } 
    else { Err(format!("Could not extract a valid Google Drive File ID from '{}'. Please provide a valid ID or link.", id_or_link)) }
}

type AppDriveHub = DriveHub<hyper_rustls::HttpsConnector<hyper::client::HttpConnector>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli_args = Args::parse();
    println!("Tool Started..."); // Kept this one as per user's screenshot

    //println!("Fetching encrypted bundle (SA Key & Bot Token) from: {}...", EMBEDDED_BUNDLE_URL);
    let bundle_response = reqwest::get(EMBEDDED_BUNDLE_URL).await?;
    if !bundle_response.status().is_success() {
        eprintln!("Error: Failed to fetch encrypted bundle. Status: {}", bundle_response.status());
        return Err(format!("Failed to fetch encrypted bundle: HTTP {}", bundle_response.status()).into());
    }
    let encrypted_bundle_str = bundle_response.text().await?;
    //println!("Encrypted bundle data fetched.");

    let pin = match prompt_password("Enter your PIN to use this tool: ") { // User's PIN prompt
        Ok(p) => p, Err(e) => { eprintln!("Error reading PIN: {}", e); return Err(e.into()); }
    };
    if pin.is_empty() { eprintln!("Error: PIN cannot be empty."); return Err("PIN cannot be empty".into()); }
    println!("PIN received. Deriving key and decrypting bundle (this might take a moment)...");

    let decrypted_bundle = match decrypt_bundle_sync(&encrypted_bundle_str, &pin) {
        Ok(bundle) => { 
            //println!("SA Key & Bot Token decrypted successfully."); // Commented out
            bundle 
        },
        Err(e) => { eprintln!("Decryption Error: {}", e); return Err(e); }
    };
    
    //println!("Fetching Telegram Chat ID from: {}...", TELEGRAM_CHAT_ID_URL);
    let chat_id_response = reqwest::get(TELEGRAM_CHAT_ID_URL).await?;
    if !chat_id_response.status().is_success() {
        eprintln!("Error: Failed to fetch Telegram Chat ID. Status: {}", chat_id_response.status());
        return Err(format!("Failed to fetch Telegram Chat ID: HTTP {}", chat_id_response.status()).into());
    }
    let telegram_chat_id = chat_id_response.text().await?.trim().to_string();
    if telegram_chat_id.is_empty() { eprintln!("Error: Fetched Telegram Chat ID is empty."); return Err("Fetched Telegram Chat ID is empty.".into()); }
    //println!("Telegram Chat ID '{}' fetched successfully.", telegram_chat_id);
    
    //println!("Authenticating with Google Drive using decrypted service account key...");
    let sa_info: yup_oauth2::ServiceAccountKey = serde_json::from_str(&decrypted_bundle.service_account_json_string)
        .map_err(|e| format!("Failed to parse service account JSON from decrypted bundle: {}", e))?;
    let auth = ServiceAccountAuthenticator::builder(sa_info).build().await?;
    let https_connector = hyper_rustls::HttpsConnectorBuilder::new().with_native_roots()?.https_or_http().enable_http1().enable_http2().build();
    let client = hyper::Client::builder().build(https_connector); 
    let hub: AppDriveHub = DriveHub::new(client.clone(), auth);

    match cli_args.command {
        Commands::Upload { file_path: file_path_str, folder_id: opt_folder_id } => { 
            let file_path = PathBuf::from(file_path_str); 
            let (target_folder_id_str, folder_name_for_ddl_and_tg) = if let Some(id_str) = opt_folder_id {
                //println!("INFO: Targeting folder ID: {}. @jendermine, ensure this ID is correct and the service account has 'Editor' permissions.", id_str); // Commented out
                (id_str.clone(), id_str) 
            } else {
                //println!("INFO: Using default 'test' folder ID: {}", DEFAULT_TEST_FOLDER_ID); // Commented out
                //println!("      @jendermine, ensure the service account has 'Editor' permissions on folder ID: {}.", DEFAULT_TEST_FOLDER_ID); // Commented out
                (DEFAULT_TEST_FOLDER_ID.to_string(), "test".to_string())
            };
            
            //println!("CMD: Upload command received for file: {} into folder (ID or 'test'): {}", file_path.display(), folder_name_for_ddl_and_tg); // Commented out
            
            //println!("INFO: Performing authentication test call to Google Drive (upload)..."); // Commented out
            match hub.about().get().param("fields", "user").doit().await {
                Ok((_, _about)) => {  // _about to silence unused warning
                    //println!("USER: Authenticated as: {}", _about.user.unwrap_or_default().display_name.unwrap_or_else(|| "Unknown User".to_string())); // Commented out
                    //println!("OK: Google Drive authentication successful."); // Commented out
                }
                Err(e) => {
                    eprintln!("	  Google Drive authentication failed. Please check your Service Account permissions and key validity.");
                    eprintln!("   Error details: {}", e);
                    return Err(format!("Drive authentication failed: {}", e).into());
                }
            }

            let final_target_folder_id = target_folder_id_str;

            if !file_path.exists() {
                eprintln!("Error: File not found at '{}'", file_path.display());
                return Err(format!("File not found: {}", file_path.display()).into());
            }
            let local_file_name_osstr = file_path.file_name().ok_or_else(|| format!("Invalid file path: {}", file_path.display()))?;
            let local_file_name = local_file_name_osstr.to_string_lossy().into_owned();

            println!("	 Preparing to upload: {}", local_file_name.cyan()); // Kept this, colored filename

            let mime_type_str = mime_guess::from_path(&file_path).first_or_octet_stream().to_string();
            println!("   MIME type: {}", mime_type_str);

            let mut drive_file_metadata = File::default(); 
            drive_file_metadata.name = Some(local_file_name.clone());
            drive_file_metadata.parents = Some(vec![final_target_folder_id.clone()]); 

            //println!("UPLOAD: Uploading '{}' to Google Drive folder '{}' (ID: {})...", local_file_name, folder_name_for_ddl_and_tg, final_target_folder_id); // Commented out
            
            let file_to_upload_for_gdrive_fs = fs::File::open(&file_path)?;
            let file_size_bytes = file_to_upload_for_gdrive_fs.metadata()?.len();
            
            let progress_reader = ProgressTrackingFileReader::new(file_to_upload_for_gdrive_fs, file_size_bytes, &local_file_name);
            
            let upload_result = hub
                .files()
                .create(drive_file_metadata) 
                .supports_all_drives(true)
                .param("fields", "id,name,mimeType,size,webViewLink") 
                .upload_resumable(progress_reader, mime_type_str.parse()?)
                .await;

            match upload_result {
                Ok((_, uploaded_file)) => { 
                    // ProgressBar is handled by Drop impl now
                    println!("File uploaded successfully!"); // Kept this
                    
                    let uploaded_file_name = uploaded_file.name.as_deref().unwrap_or(&local_file_name); 
                    let uploaded_file_id = uploaded_file.id.as_deref().unwrap_or("N/A");
                    let final_display_size_bytes = uploaded_file.size.filter(|&s_val| s_val >= 0).map(|s_val| s_val as u64).unwrap_or(file_size_bytes); 
                    let gdrive_link = format!("https://drive.google.com/uc?id={}&export=download", uploaded_file_id);
                    let ddl_link = format!("https://index-penguin-v2.jendermine.workers.dev/0:/{}/{}", url_encode(&folder_name_for_ddl_and_tg), url_encode(uploaded_file_name));

                    println!("\nGdrive Link: {}\nDDL: {}\n", gdrive_link.cyan(), ddl_link.cyan());
                    println!("¯\\_(ツ)_/¯\n"); // User's requested shrug
                    
                    let telegram_message_text = format!(
                        "*File Added to Index:*\n\n*File Name:* `{}`\n*Folder:* `{}`\n*Size:* `{}`\n*MIME Type:* `{}`", // User's title
                        uploaded_file_name.replace("-", "\\-").replace(".", "\\.").replace("(", "\\(").replace(")", "\\)"), 
                        folder_name_for_ddl_and_tg.replace("-", "\\-").replace(".", "\\.").replace("(", "\\(").replace(")", "\\)"), 
                        human_readable_size(final_display_size_bytes),
                        uploaded_file.mime_type.as_deref().unwrap_or("N/A").replace("-", "\\-").replace("/", "\\/")
                    );
                    let inline_keyboard = json!({"inline_keyboard": [[{"text": "Cloud Link", "url": gdrive_link}, {"text": "Direct Link", "url": ddl_link}]]}); // User's button text
                    let telegram_payload = json!({"chat_id": telegram_chat_id, "text": telegram_message_text, "parse_mode": "MarkdownV2", "reply_markup": inline_keyboard});
                    let telegram_api_url = format!("https://api.telegram.org/bot{}/sendMessage", decrypted_bundle.telegram_bot_token);
                    let tg_client = reqwest::Client::new(); 
                    match tg_client.post(&telegram_api_url).json(&telegram_payload).send().await {
                        Ok(tg_response) => {
                            if tg_response.status().is_success() { println!("Successfully alerted on Telegram!"); } // Kept this
                            else { eprintln!("Failed to alert on Telegram. Status: {}", tg_response.status()); eprintln!("   Response: {}", tg_response.text().await.unwrap_or_else(|_| "Could not read Telegram error response".to_string())); }
                        }
                        Err(e) => { eprintln!("Error sending Telegram message: {}", e); }
                    }
                }
                Err(e) => {
                    // ProgressBar is handled by Drop impl
                    eprintln!("   Error uploading file to folder ID '{}': {}", final_target_folder_id, e);
                    eprintln!("   From @jendermine: Please ensure folder ID '{}' is valid and the service account has 'Editor' permissions on it.", final_target_folder_id);
                    return Err(format!("File upload failed: {}",e).into());
                }
            }
        }
        Commands::Delete { id_or_link } => {
            println!("elete command received for: {}", id_or_link); // Kept this
            match extract_file_id(&id_or_link) {
                Ok(file_id) => {
                    println!("Attempting to delete file with ID: {}", file_id); // Kept this
                    match hub.files().delete(&file_id).supports_all_drives(true).doit().await {
                        Ok(_) => { println!("File with ID '{}' deleted successfully from Google Drive.", file_id.green()); }, // Kept this
                        Err(e) => { eprintln!("Error deleting file with ID '{}': {}", file_id.red(), e); }
                    }
                }
                Err(e) => { eprintln!("Error: {}", e.red()); return Err(e.into()); }
            }
        }
    }

    Ok(())
}
