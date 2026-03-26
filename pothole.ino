#include <Wire.h>
#include <WiFi.h>
#include <FirebaseESP32.h>
#include <SPIFFS.h>

#define HAS_MPU6050  1
#define HAS_GPS      1

#if HAS_MPU6050
  #include <MPU6050.h>
  MPU6050 mpu;
#endif

#if HAS_GPS
  #include <TinyGPSPlus.h>
  #include <HardwareSerial.h>
  TinyGPSPlus gps;
  HardwareSerial gpsSerial(2);
#endif

#define WIFI_SSID      "ibrahim"
#define WIFI_PASSWORD  "1234567890"
#define FIREBASE_HOST  "pothole-map-38d98-default-rtdb.firebaseio.com"
#define FIREBASE_AUTH  "ytPayaiaPuRO0TKxWKdoVeNEN89oWiPsGWIYoIre"

#define BUZZER_PIN     4
#define TEST_BUTTON    0

#define MINOR_G        2.0
#define MODERATE_G     3.0
#define SEVERE_G       5.0
#define Y_REJECT       1.5
#define DEBOUNCE_MS    2000

//test 
float testLat = 19.0760;
float testLng = 72.8777;

FirebaseData   fbData;
FirebaseConfig fbConfig;
FirebaseAuth   fbAuth;

int    reportCount   = 0;
bool   wifiConnected = false;
unsigned long lastTrigger = 0;

String classifySeverity(float zImpact);
void handleDetection(String severity, float gForce,
                     float overrideLat = 0, float overrideLng = 0);

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println("\n=== SusX Pothole Detection System ===");

  pinMode(BUZZER_PIN, OUTPUT);
  pinMode(TEST_BUTTON, INPUT_PULLUP);

  if (!SPIFFS.begin(true)) {
    Serial.println("[WARN] SPIFFS init failed");
  } else {
    Serial.println("[OK] SPIFFS ready");
  }

  #if HAS_MPU6050
    Wire.begin();
    mpu.initialize();
    if (mpu.testConnection()) {
      Serial.println("[OK] MPU6050 connected");
    } else {
      Serial.println("[ERR] MPU6050 not found - check wiring");
    }
  #else
    Serial.println("[INFO] MPU6050 disabled - test mode active");
    Serial.println("[INFO] Press BOOT button to simulate pothole");
  #endif

  #if HAS_GPS
    gpsSerial.begin(9600, SERIAL_8N1, 16, 17);
    Serial.println("[OK] GPS serial started");
  #else
    Serial.println("[INFO] GPS disabled - using fixed test coordinates");
  #endif

  connectWiFi();
  setupFirebase();

  uploadBuffered();

  Serial.println("\n[READY] System running...\n");
}

void loop() {
  #if HAS_GPS
    while (gpsSerial.available()) {
      gps.encode(gpsSerial.read());
    }
  #endif

  #if HAS_MPU6050
    int16_t ax, ay, az;
    mpu.getAcceleration(&ax, &ay, &az);

    float zG      = az / 16384.0;
    float yG      = abs(ay / 16384.0);
    float zImpact = abs(zG) - 1.0;

    bool debounceOk = (millis() - lastTrigger) > DEBOUNCE_MS;

    if (zImpact > MINOR_G && yG < Y_REJECT && debounceOk) {
      String severity = classifySeverity(zImpact);
      handleDetection(severity, zImpact);
    }
  #endif

  #if !HAS_MPU6050
    if (digitalRead(TEST_BUTTON) == LOW) {
      bool debounceOk = (millis() - lastTrigger) > DEBOUNCE_MS;
      if (debounceOk) {
        float fakeG;
        String severity;
        int cycle = reportCount % 3;
        if (cycle == 0)      { fakeG = 5.9; severity = "Severe"; }
        else if (cycle == 1) { fakeG = 3.7; severity = "Moderate"; }
        else                 { fakeG = 2.3; severity = "Minor"; }

        float lat = testLat + (random(-50, 50) / 10000.0);
        float lng = testLng + (random(-50, 50) / 10000.0);

        handleDetection(severity, fakeG, lat, lng);
      }
    }
  #endif

  delay(50);
}

String classifySeverity(float zImpact) {
  if (zImpact >= SEVERE_G)   return "Severe";
  if (zImpact >= MODERATE_G) return "Moderate";
  return "Minor";
}

void handleDetection(String severity, float gForce,
                     float overrideLat, float overrideLng) {
  lastTrigger = millis();
  reportCount++;

  Serial.println("──────────────────────────────");
  Serial.printf("[POTHOLE] %s | %.2fg\n", severity.c_str(), gForce);

  float lat = overrideLat;
  float lng = overrideLng;

  #if HAS_GPS
    if (overrideLat == 0 && gps.location.isValid()) {
      lat = gps.location.lat();
      lng = gps.location.lng();
      Serial.printf("[GPS] %.6f, %.6f\n", lat, lng);
    } else if (overrideLat == 0) {
      Serial.println("[GPS] No fix yet - using last known");
      lat = testLat;
      lng = testLng;
    }
  #else
    if (overrideLat == 0) {
      lat = testLat;
      lng = testLng;
    }
  #endif

  buzzAlert(severity);

  if (WiFi.status() == WL_CONNECTED) {
    sendToFirebase(lat, lng, severity, gForce);
  } else {
    Serial.println("[WIFI] Offline - buffering to SPIFFS");
    bufferToSPIFFS(lat, lng, severity, gForce);
    connectWiFi();
  }
}

void sendToFirebase(float lat, float lng, String severity, float gForce) {
  String path = "/potholes/report_" + String(reportCount);

  FirebaseJson json;
  json.set("lat",          lat);
  json.set("lng",          lng);
  json.set("severity",     severity);
  json.set("g_force",      gForce);
  json.set("timestamp",    (int)(millis() / 1000));
  json.set("confirmed",    false);
  json.set("report_count", 1);

  if (Firebase.setJSON(fbData, path, json)) {
    Serial.println("[FB] Sent OK → " + path);
  } else {
    Serial.println("[FB] Failed: " + fbData.errorReason());
    bufferToSPIFFS(lat, lng, severity, gForce);
  }
}

void bufferToSPIFFS(float lat, float lng, String severity, float gForce) {
  File f = SPIFFS.open("/buffer.txt", FILE_APPEND);
  if (f) {
    f.printf("%.6f,%.6f,%s,%.2f\n", lat, lng, severity.c_str(), gForce);
    f.close();
    Serial.println("[SPIFFS] Buffered");
  }
}

void uploadBuffered() {
  if (!SPIFFS.exists("/buffer.txt")) return;

  Serial.println("[SPIFFS] Uploading buffered data...");
  File f = SPIFFS.open("/buffer.txt", FILE_READ);
  int uploaded = 0;

  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();
    if (line.length() == 0) continue;

    int c1 = line.indexOf(',');
    int c2 = line.indexOf(',', c1 + 1);
    int c3 = line.indexOf(',', c2 + 1);

    float  lat = line.substring(0, c1).toFloat();
    float  lng = line.substring(c1 + 1, c2).toFloat();
    String sev = line.substring(c2 + 1, c3);
    float  gf  = line.substring(c3 + 1).toFloat();

    sendToFirebase(lat, lng, sev, gf);
    uploaded++;
    delay(300);
  }

  f.close();
  SPIFFS.remove("/buffer.txt");
  Serial.printf("[SPIFFS] Uploaded %d buffered reports\n", uploaded);
}

void buzzAlert(String severity) {
  int beeps = 1;
  if (severity == "Moderate") beeps = 2;
  if (severity == "Severe")   beeps = 3;

  for (int i = 0; i < beeps; i++) {
    digitalWrite(BUZZER_PIN, HIGH); delay(150);
    digitalWrite(BUZZER_PIN, LOW);
    if (i < beeps - 1) delay(100);
  }
  Serial.printf("[BUZZ] %d beep(s)\n", beeps);
}

void connectWiFi() {
  if (WiFi.status() == WL_CONNECTED) return;

  Serial.printf("[WIFI] Connecting to %s", WIFI_SSID);
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);

  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 20) {
    delay(500);
    Serial.print(".");
    tries++;
  }

  if (WiFi.status() == WL_CONNECTED) {
    wifiConnected = true;
    Serial.println("\n[WIFI] Connected: " + WiFi.localIP().toString());
  } else {
    Serial.println("\n[WIFI] Failed - will buffer offline");
  }
}

void setupFirebase() {
  fbConfig.host                        = FIREBASE_HOST;
  fbConfig.signer.tokens.legacy_token = FIREBASE_AUTH;
  Firebase.begin(&fbConfig, &fbAuth);
  Firebase.reconnectWiFi(true);
  Serial.println("[FB] Firebase initialized");
}