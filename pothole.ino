// ============================================================
//  SusX Pothole Detection System  — Firmware v4.3.0
//  ESP32 + MPU6050 + NEO-6M GPS + Firebase
//
//  CHANGELOG v4.1.0 (industry-grade hardening): all 12 fixes
//
//  CHANGELOG v4.2.0 (offline-first WiFi):
//   FEAT-01  Multi-SSID support
//   FEAT-02  Status LED
//   FEAT-03  Offline counter in Serial
//   FEAT-04  Auto-sync on reconnect
//   FEAT-05  Scan-before-connect
//   FEAT-06  Connection quality log
//
//  CHANGELOG v4.3.0 (bug fixes):
//   BUGFIX-1  GPS quality gate changed from || to && in parseGPS()
//             — prevents logging invalid coordinates when HDOP=99
//   BUGFIX-2  uploadBuffered() now rewrites SPIFFS keeping only
//             failed lines — prevents duplicate re-upload on retry
//   BUGFIX-3  buzzAlert() made non-blocking using state machine
//             — was blocking IMU sampling for up to 280ms
//   BUGFIX-4  medianOf5() now uses MEDIAN_WINDOW constant with
//             static_assert guard — was silently hardcoded to 5
//   BUGFIX-5  Firebase path now uses deviceId + currentUnixMillis()
//             — millis()-based path caused collisions after reboot
// ============================================================

#include <Wire.h>
#include <WiFi.h>
#include <FirebaseESP32.h>
#include <SPIFFS.h>
#include <MPU6050.h>
#include <TinyGPSPlus.h>
#include <HardwareSerial.h>
#include <esp_system.h>
#include <esp_task_wdt.h>
#include <time.h>
#include <sys/time.h>
#include <math.h>

// ────────────────────────────────────────────────────────────
//  Version
// ────────────────────────────────────────────────────────────
#define FIRMWARE_VERSION        "4.3.0"

// ────────────────────────────────────────────────────────────
//  Known WiFi networks — scan-and-connect (FEAT-01 / FEAT-05)
// ────────────────────────────────────────────────────────────
struct WifiCred { const char *ssid; const char *pass; };
static const WifiCred KNOWN_NETWORKS[] = {
    { "OPPO K10 5G",    "Simple@2018" },
    { "Colosseum 2",    "Dbit@2026"   },
    { "Ibrahim",        "1234567890"  },
};
static const int KNOWN_NETWORK_COUNT =
    (int)(sizeof(KNOWN_NETWORKS) / sizeof(KNOWN_NETWORKS[0]));

// ────────────────────────────────────────────────────────────
//  Firebase credentials
// ────────────────────────────────────────────────────────────
#define FIREBASE_HOST  "pothole-map-38d98-default-rtdb.firebaseio.com"
#define FIREBASE_AUTH  "kgB5RA7NGONmr5TU0riMgrRQIphpkwlYFR3LCo7l"

// ────────────────────────────────────────────────────────────
//  Hardware pins
// ────────────────────────────────────────────────────────────
#define BUZZER_PIN              4
#define GPS_RX_PIN              16
#define GPS_TX_PIN              17
#define GPS_BAUD                9600
#define BATTERY_ADC_PIN         34
#define STATUS_LED_PIN          2

// ────────────────────────────────────────────────────────────
//  Sampling
// ────────────────────────────────────────────────────────────
#define SAMPLE_RATE_HZ          100
#define SAMPLE_INTERVAL_US      10000
#define BUFFER_SIZE             128

// ────────────────────────────────────────────────────────────
//  Speed gates
// ────────────────────────────────────────────────────────────
#define MIN_SPEED_KMH           3.0f
#define MAX_SPEED_KMH           150.0f
#define NO_GPS_SPEED_ASSUMED    15.0f

// ────────────────────────────────────────────────────────────
//  Jerk detection
// ────────────────────────────────────────────────────────────
#define BASE_JERK_THRESH        7.0f
#define SPEED_JERK_COEFF        0.12f
#define JERK_NOISE_MULT         3.5f
#define JERK_NOISE_ADAPT_CAP    4.0f

// ────────────────────────────────────────────────────────────
//  Multi-axis classifiers
// ────────────────────────────────────────────────────────────
#define ROLL_THRESH             25.0f
#define PITCH_THRESH            30.0f
#define ZY_RATIO_LIMIT          2.8f
#define BRAKE_X_THRESH          4.5f
#define YAW_TURN_THRESH         45.0f

// ────────────────────────────────────────────────────────────
//  Severity thresholds (m/s²)
// ────────────────────────────────────────────────────────────
#define SEVERE_MS2              45.0f
#define MODERATE_MS2            25.0f

// ────────────────────────────────────────────────────────────
//  Deduplication / debounce
// ────────────────────────────────────────────────────────────
#define DEBOUNCE_MS             3000
#define GPS_DEDUP_RADIUS_M      12.0f
#define DEDUP_RING_SIZE         20

// ────────────────────────────────────────────────────────────
//  Filters
// ────────────────────────────────────────────────────────────
#define LPF_ALPHA               0.45f
#define HPF_ALPHA               0.93f

// ────────────────────────────────────────────────────────────
//  Calibration
// ────────────────────────────────────────────────────────────
#define CALIBRATION_SAMPLES     500
#define CALIB_STDDEV_LIMIT      0.12f
#define CALIB_MAX_RETRIES       3

// ────────────────────────────────────────────────────────────
//  Periodic recalibration
// ────────────────────────────────────────────────────────────
#define RECALIB_INTERVAL_MS     300000UL
#define RECALIB_STILL_MS        3000

// ────────────────────────────────────────────────────────────
//  Motion / GPS quality gates
// ────────────────────────────────────────────────────────────
#define MIN_MOTION_SCORE        2.0f
#define GPS_HDOP_LIMIT          5.0f
#define GPS_MIN_SATS            4

// ────────────────────────────────────────────────────────────
//  Scoring thresholds
// ────────────────────────────────────────────────────────────
#define CONFIDENCE_HIGH         0.88f
#define CONFIDENCE_MED          0.62f
#define CONFIDENCE_LOW          0.38f
#define MIN_POTHOLE_SCORE       0.50f
#define BORDERLINE_SCORE        0.32f

// ────────────────────────────────────────────────────────────
//  System
// ────────────────────────────────────────────────────────────
#define WDT_TIMEOUT_S           30
#define EPOCH_VALID_AFTER       1700000000UL
#define NTP_TIMEZONE_OFF        19800

// ────────────────────────────────────────────────────────────
//  Signal processing
// ────────────────────────────────────────────────────────────
#define MEDIAN_WINDOW           5
#define EVENT_CAPTURE_TICKS     35
#define BASELINE_WINDOW         200

// ────────────────────────────────────────────────────────────
//  Battery / SPIFFS
// ────────────────────────────────────────────────────────────
#define BATT_DIVIDER_RATIO      2.0f
#define BATT_LOW_VOLTS          3.3f
#define SPIFFS_MAX_BUFFER       50
#define SPIFFS_ROTATE_LINES     10

// BUGFIX-4: static assert so if MEDIAN_WINDOW ever changes,
// medianOfN() won't silently sort the wrong number of elements
static_assert(MEDIAN_WINDOW == 5, "medianOfN() is implemented for exactly 5 elements. "
              "Update the sort and return index if you change MEDIAN_WINDOW.");

// ────────────────────────────────────────────────────────────
//  Objects
// ────────────────────────────────────────────────────────────
MPU6050         mpu;
TinyGPSPlus     gps;
HardwareSerial  gpsSerial(2);
FirebaseData    fbData;
FirebaseConfig  fbConfig;
FirebaseAuth    fbAuth;

// ────────────────────────────────────────────────────────────
//  IMU sample
// ────────────────────────────────────────────────────────────
struct ImuSample {
    float         az_filt;
    float         ay_filt;
    float         ax_filt;
    float         az_hp;
    float         ay_hp;
    float         roll_rate;
    float         pitch_rate;
    float         yaw_rate;
    float         temperature;
    unsigned long timestamp;
};

ImuSample  ringBuf[BUFFER_SIZE];
int        bufHead  = 0;
int        bufCount = 0;

// ────────────────────────────────────────────────────────────
//  Filter states
// ────────────────────────────────────────────────────────────
float lpf_z = 0, lpf_y = 0, lpf_x = 0;
float hpf_z_in = 0, hpf_z_out = 0;
float hpf_y_in = 0, hpf_y_out = 0;

// ────────────────────────────────────────────────────────────
//  Calibration state
// ────────────────────────────────────────────────────────────
float gravOffZ = 9.81f, gravOffX = 0, gravOffY = 0;
float calibStdZ = 0;
float gyroOffX = 0, gyroOffY = 0, gyroOffZ = 0;
float tempCompCoeff = 0.002f;
float calibTemp = 25.0f;

// ────────────────────────────────────────────────────────────
//  Median buffers
// ────────────────────────────────────────────────────────────
float medianBufZ[MEDIAN_WINDOW];
float medianBufY[MEDIAN_WINDOW];
float medianBufX[MEDIAN_WINDOW];
uint8_t medianIdx = 0;

// ────────────────────────────────────────────────────────────
//  Adaptive baseline
// ────────────────────────────────────────────────────────────
float baselineRmsZ          = 0.3f;
float baselineRmsAccum      = 0;
int   baselineSampleCount   = 0;

// ────────────────────────────────────────────────────────────
//  Deduplication ring
// ────────────────────────────────────────────────────────────
struct DedupPoint { float lat; float lng; unsigned long ms; };
DedupPoint dedupRing[DEDUP_RING_SIZE];
int dedupIdx   = 0;
int dedupCount = 0;

// ────────────────────────────────────────────────────────────
//  Detection FSM
// ────────────────────────────────────────────────────────────
enum DetectState { IDLE, EVENT_CAPTURE, CLASSIFYING };
DetectState   detectState   = IDLE;
int           eventTimer    = 0;
unsigned long eventStartMs  = 0;
unsigned long lastTriggerMs = 0;

// ────────────────────────────────────────────────────────────
//  GPS / motion state
// ────────────────────────────────────────────────────────────
float currentSpeedKmh   = 0;
float currentLat        = 0, currentLng = 0;
float currentHdop       = 99.0f;
float currentHeading    = 0;
int   currentSatCount   = 0;
bool  gpsValid          = false;
float lastMpuTemp       = 25.0f;

// ────────────────────────────────────────────────────────────
//  System health / counters
// ────────────────────────────────────────────────────────────
int           reportCount       = 0;
int           rejectCount       = 0;
unsigned long uptimeStartMs     = 0;
unsigned long lastRecalibMs     = 0;
unsigned long lastWifiAttemptMs = 0;
int           wifiBackoffSec    = 2;
bool          sensorHealthy     = true;
float         batteryVoltage    = 4.2f;
int           spiffsBufferCount = 0;

// ── Offline-first tracking ────────────────────────────────────
int           offlineEventCount  = 0;
unsigned long lastLedToggleMs    = 0;
bool          ledState           = false;

enum LedMode { LED_SOLID, LED_SLOW_BLINK, LED_FAST_BLINK };
LedMode       currentLedMode    = LED_SLOW_BLINK;

String deviceId = "";

// ────────────────────────────────────────────────────────────
//  Fallback GPS (Mumbai centre)
// ────────────────────────────────────────────────────────────
const float FALLBACK_LAT = 19.0760f;
const float FALLBACK_LNG = 72.8777f;

// ────────────────────────────────────────────────────────────
//  BUGFIX-3: Non-blocking buzzer state machine
// ────────────────────────────────────────────────────────────
struct BuzzState {
    int           totalBeeps  = 0;
    int           beepsDone   = 0;
    int           onMs        = 0;
    int           offMs       = 0;
    bool          buzzerOn    = false;
    unsigned long lastChangeMs = 0;
    bool          active      = false;
} buzzSM;

// ────────────────────────────────────────────────────────────
//  Forward declarations
// ────────────────────────────────────────────────────────────
void  calibrateSensor();
bool  validateCalibration();
void  attemptRecalibration();
void  resetJerk();

ImuSample readAndFilter();
float applyLPF(float in, float &state);
float applyHPF(float in, float &pIn, float &pOut);
float medianOfN(float *buf);
void  pushToBuffer(const ImuSample &s);
ImuSample bufferAt(int i);
float computeJerk(float z);
float dynamicJerkThresh(float spd);
bool  isMoving(const ImuSample &s);
void  runDetectionFSM(const ImuSample &s);
String classifyAnomaly(int n, float &conf);
String classifySeverity(float peakZ, float rmsZ, float rmsY);
float computeRMS(int start, int count, int axis);
float computeCrestFactor(float peak, float rms);
float computeEnergy(int start, int count);
float computeSpectralEntropy(int start, int count);
bool  isDuplicateLocation(float lat, float lng);
void  addToDedupRing(float lat, float lng);
float haversineM(float lat1, float lng1, float lat2, float lng2);
void  handleConfirmedEvent(const String &type, const String &sev, float gForce, float conf);
void  sendToFirebase(float lat, float lng, const String &type, const String &sev,
                     float gForce, float conf, uint64_t ts);
void  bufferToSPIFFS(float lat, float lng, const String &type, const String &sev,
                     float gForce, uint64_t ts);
void  rotateSPIFFS(int linesToDrop);
void  uploadBuffered();
void  startBuzzAlert(const String &sev);
void  updateBuzzer();
void  connectWiFi();
int   scanAndPickNetwork();
void  updateLed();
void  setupFirebase();
void  parseGPS();
void  generateDeviceId();
void  syncClock();
bool  hasValidClock();
uint64_t currentUnixMillis();
float readBattery();
float readMpuTemp();
void  updateBaseline(float z);
void  checkSpiffsHealth();
void  printBanner();
void  printConfig();
void  printEvent(const String &type, const String &sev, float gForce,
                 float lat, float lng, float conf);

// ============================================================
//  SETUP
// ============================================================
void setup() {
    Serial.begin(115200);
    delay(400);
    printBanner();

    uptimeStartMs = millis();
    generateDeviceId();

    esp_task_wdt_init(WDT_TIMEOUT_S, true);
    esp_task_wdt_add(NULL);

    pinMode(BUZZER_PIN, OUTPUT);
    digitalWrite(BUZZER_PIN, LOW);

    pinMode(STATUS_LED_PIN, OUTPUT);
    digitalWrite(STATUS_LED_PIN, LOW);
    currentLedMode = LED_SLOW_BLINK;

    if (!SPIFFS.begin(true)) {
        Serial.println(F("[ERR]  SPIFFS mount failed — formatting"));
        SPIFFS.format();
        SPIFFS.begin(true);
    }
    checkSpiffsHealth();

    Wire.begin(21, 22);
    Wire.setClock(400000);

    mpu.initialize();
    mpu.setFullScaleAccelRange(MPU6050_ACCEL_FS_4);
    mpu.setFullScaleGyroRange(MPU6050_GYRO_FS_500);
    mpu.setDLPFMode(MPU6050_DLPF_BW_42);
    mpu.setRate(9);

    uint8_t id = mpu.getDeviceID();
    sensorHealthy = (id == 0x34 || id == 0x38 || mpu.testConnection());
    if (sensorHealthy) {
        Serial.printf("[OK]   MPU6050 (0x%02X) | ±4g | ±500°/s | DLPF=42Hz | ODR=100Hz\n", id);
    } else {
        Serial.printf("[ERR]  MPU6050 not found (0x%02X)\n", id);
    }

    gpsSerial.begin(GPS_BAUD, SERIAL_8N1, GPS_RX_PIN, GPS_TX_PIN);
    Serial.println(F("[OK]   GPS UART2 @ 9600"));

    batteryVoltage = readBattery();
    Serial.printf("[BATT] %.2fV\n", batteryVoltage);

    calibTemp = readMpuTemp();
    Serial.printf("[TEMP] MPU die: %.1f°C\n", calibTemp);

    Serial.println(F("[CAL]  Calibrating — keep device STILL..."));
    int calibAttempt = 0;
    do {
        calibrateSensor();
        calibAttempt++;
        if (calibAttempt >= CALIB_MAX_RETRIES) {
            Serial.println(F("[CAL]  Max retries — proceeding with best effort"));
            break;
        }
    } while (!validateCalibration());

    for (int i = 0; i < MEDIAN_WINDOW; i++) {
        medianBufZ[i] = 0;
        medianBufY[i] = 0;
        medianBufX[i] = 0;
    }

    resetJerk();

    connectWiFi();
    setupFirebase();
    uploadBuffered();

    lastRecalibMs = millis();
    printConfig();
    Serial.println(F("\n[READY] Detection pipeline active\n"));
}

// ============================================================
//  MAIN LOOP
// ============================================================
void loop() {
    static unsigned long lastSampleUs  = 0;
    static unsigned long lastDebugMs   = 0;
    static unsigned long lastHealthMs  = 0;
    static unsigned long lastBattMs    = 0;

    unsigned long nowUs = micros();
    unsigned long nowMs = millis();

    esp_task_wdt_reset();
    updateLed();
    updateBuzzer();   // BUGFIX-3: non-blocking buzzer tick
    parseGPS();

    if ((nowUs - lastSampleUs) < SAMPLE_INTERVAL_US) return;
    lastSampleUs = nowUs;

    if (!sensorHealthy) {
        Wire.begin(21, 22);
        Wire.setClock(400000);
        mpu.initialize();
        mpu.setFullScaleAccelRange(MPU6050_ACCEL_FS_4);
        mpu.setFullScaleGyroRange(MPU6050_GYRO_FS_500);
        mpu.setDLPFMode(MPU6050_DLPF_BW_42);
        mpu.setRate(9);
        sensorHealthy = mpu.testConnection();
        if (sensorHealthy) {
            Serial.println(F("[RECOV] MPU6050 recovered"));
            calibrateSensor();
            resetJerk();
        }
        return;
    }

    ImuSample s = readAndFilter();
    pushToBuffer(s);
    updateBaseline(s.az_hp);
    runDetectionFSM(s);

    if ((nowMs - lastRecalibMs) > RECALIB_INTERVAL_MS && detectState == IDLE) {
        float tempNow = readMpuTemp();
        if (fabsf(tempNow - calibTemp) > 5.0f) {
            Serial.printf("[TEMP] Drift %.1f°C → recalibrating\n", tempNow - calibTemp);
            calibTemp = tempNow;
        }
        attemptRecalibration();
        lastRecalibMs = nowMs;
    }

    if (nowMs - lastDebugMs > 3000) {
        lastDebugMs = nowMs;
        float upMin = (nowMs - uptimeStartMs) / 60000.0f;
        const char *wifiStr = (WiFi.status() == WL_CONNECTED)
                              ? WiFi.SSID().c_str() : "OFFLINE";
        Serial.printf(
            "[DBG] Z:%.2f Y:%.2f X:%.2f | R:%.1f P:%.1f | "
            "Spd:%.1f | Sat:%d HDOP:%.1f | %s | "
            "Base:%.3f | Up:%.1fm | Rpt:%d Rej:%d | "
            "Buf:%d WiFi:%s\n",
            s.az_filt, s.ay_filt, s.ax_filt,
            s.roll_rate, s.pitch_rate,
            currentSpeedKmh, currentSatCount, currentHdop,
            gpsValid ? "FIX" : "---",
            baselineRmsZ, upMin, reportCount, rejectCount,
            spiffsBufferCount, wifiStr);
    }

    if (nowMs - lastHealthMs > 30000) {
        lastHealthMs = nowMs;
        int16_t tx, ty, tz, gx, gy, gz;
        mpu.getMotion6(&tx, &ty, &tz, &gx, &gy, &gz);
        if (tx == 0 && ty == 0 && tz == 0 && gx == 0 && gy == 0 && gz == 0) {
            Serial.println(F("[HEALTH] MPU6050 all-zero — marking unhealthy"));
            sensorHealthy = false;
        }
    }

    if (nowMs - lastBattMs > 60000) {
        lastBattMs    = nowMs;
        batteryVoltage = readBattery();
        if (batteryVoltage < BATT_LOW_VOLTS && batteryVoltage > 1.0f) {
            Serial.printf("[BATT] LOW: %.2fV\n", batteryVoltage);
        }
    }

    if (WiFi.status() != WL_CONNECTED &&
        (nowMs - lastWifiAttemptMs) > (unsigned long)(wifiBackoffSec * 1000)) {
        lastWifiAttemptMs = nowMs;
        connectWiFi();
        if (WiFi.status() != WL_CONNECTED) {
            wifiBackoffSec = min(wifiBackoffSec * 2, 120);
            currentLedMode = LED_FAST_BLINK;
        } else {
            wifiBackoffSec = 2;
            currentLedMode = LED_SOLID;
            if (spiffsBufferCount > 0) {
                Serial.printf("[WIFI] Reconnected — auto-syncing %d buffered events\n",
                              spiffsBufferCount);
                uploadBuffered();
            }
        }
    }
}

// ============================================================
//  CALIBRATION
// ============================================================
void calibrateSensor() {
    const int N = CALIBRATION_SAMPLES;
    double sX = 0, sY = 0, sZ = 0;
    double sgX = 0, sgY = 0, sgZ = 0;
    static float samples[CALIBRATION_SAMPLES];

    for (int i = 0; i < N; i++) {
        int16_t ax, ay, az, gx, gy, gz;
        mpu.getMotion6(&ax, &ay, &az, &gx, &gy, &gz);
        float zVal = (az / 8192.0f) * 9.81f;
        sX += (ax / 8192.0f) * 9.81f;
        sY += (ay / 8192.0f) * 9.81f;
        sZ += zVal;
        samples[i] = zVal;
        sgX += gx / 65.5f;
        sgY += gy / 65.5f;
        sgZ += gz / 65.5f;
        delayMicroseconds(3500);
    }

    gravOffX = (float)(sX / N);
    gravOffY = (float)(sY / N);
    gravOffZ = (float)(sZ / N);
    gyroOffX = (float)(sgX / N);
    gyroOffY = (float)(sgY / N);
    gyroOffZ = (float)(sgZ / N);

    double var = 0;
    for (int i = 0; i < N; i++) {
        float d = samples[i] - gravOffZ;
        var += d * d;
    }
    calibStdZ = (float)sqrt(var / N);

    lpf_z = 0; lpf_y = 0; lpf_x = 0;
    hpf_z_in = 0; hpf_z_out = 0;
    hpf_y_in = 0; hpf_y_out = 0;

    Serial.printf("[CAL]  Grav → X:%.3f Y:%.3f Z:%.3f  |  σZ:%.4f (%s)\n",
                  gravOffX, gravOffY, gravOffZ, calibStdZ,
                  calibStdZ < CALIB_STDDEV_LIMIT ? "GOOD" : "NOISY");
    Serial.printf("[CAL]  Gyro → X:%.2f Y:%.2f Z:%.2f °/s\n",
                  gyroOffX, gyroOffY, gyroOffZ);
}

bool validateCalibration() {
    float gMag = sqrtf(gravOffX * gravOffX + gravOffY * gravOffY + gravOffZ * gravOffZ);
    bool magOk   = (gMag > 9.2f && gMag < 10.4f);
    bool noiseOk = (calibStdZ < CALIB_STDDEV_LIMIT);

    if (!magOk)   Serial.printf("[CAL]  FAIL: |g|=%.3f (expect ~9.81)\n", gMag);
    if (!noiseOk) Serial.printf("[CAL]  FAIL: σZ=%.4f > %.4f\n", calibStdZ, CALIB_STDDEV_LIMIT);
    return magOk && noiseOk;
}

void attemptRecalibration() {
    const int STILL_SAMPLES = (RECALIB_STILL_MS * SAMPLE_RATE_HZ) / 1000;

    static float  emaPeak   = 0;
    static int    collected = 0;

    ImuSample &latest = ringBuf[(bufHead - 1 + BUFFER_SIZE) % BUFFER_SIZE];
    float motion = fabsf(latest.az_filt) + fabsf(latest.ay_filt) + fabsf(latest.ax_filt);
    emaPeak = 0.95f * emaPeak + 0.05f * motion;
    collected++;

    if (collected < STILL_SAMPLES) return;

    collected = 0;
    bool vehicleStopped = (!gpsValid || currentSpeedKmh < 1.0f);
    bool sensorStill    = (emaPeak < 0.35f);

    if (sensorStill && vehicleStopped) {
        Serial.println(F("[RECAL] EMA stillness confirmed — recalibrating"));
        calibrateSensor();
        resetJerk();
        emaPeak = 0;
    } else {
        Serial.printf("[RECAL] Skipped — emaPeak=%.3f gps=%s spd=%.1f\n",
                      emaPeak, gpsValid ? "ok" : "no", currentSpeedKmh);
    }
}

// ============================================================
//  JERK RESET
// ============================================================
void resetJerk() {
    extern bool _jerkNeedsReset;
    _jerkNeedsReset = true;
}
bool _jerkNeedsReset = true;

// ============================================================
//  FILTERS
// ============================================================
float applyLPF(float in, float &state) {
    state = LPF_ALPHA * in + (1.0f - LPF_ALPHA) * state;
    return state;
}

float applyHPF(float in, float &pIn, float &pOut) {
    float out = HPF_ALPHA * (pOut + in - pIn);
    pIn  = in;
    pOut = out;
    return out;
}

// BUGFIX-4: renamed medianOf5 → medianOfN, uses MEDIAN_WINDOW constant.
// static_assert above guarantees this stays in sync if MEDIAN_WINDOW changes.
float medianOfN(float *buf) {
    float tmp[MEDIAN_WINDOW];
    memcpy(tmp, buf, sizeof(float) * MEDIAN_WINDOW);
    for (int i = 1; i < MEDIAN_WINDOW; i++) {
        float key = tmp[i];
        int j = i - 1;
        while (j >= 0 && tmp[j] > key) {
            tmp[j + 1] = tmp[j];
            j--;
        }
        tmp[j + 1] = key;
    }
    return tmp[MEDIAN_WINDOW / 2];
}

// ============================================================
//  SAMPLE ACQUISITION
// ============================================================
ImuSample readAndFilter() {
    int16_t axr, ayr, azr, gxr, gyr, gzr;
    mpu.getMotion6(&axr, &ayr, &azr, &gxr, &gyr, &gzr);

    float ax = (axr / 8192.0f) * 9.81f;
    float ay = (ayr / 8192.0f) * 9.81f;
    float az = (azr / 8192.0f) * 9.81f;

    float tempDelta = lastMpuTemp - calibTemp;
    float tempComp  = tempDelta * tempCompCoeff;

    uint8_t slot = medianIdx % MEDIAN_WINDOW;
    medianBufZ[slot] = az - gravOffZ - tempComp;
    medianBufY[slot] = ay - gravOffY;
    medianBufX[slot] = ax - gravOffX;
    medianIdx = (medianIdx + 1) % MEDIAN_WINDOW;

    bool medianReady = (bufCount >= MEDIAN_WINDOW);
    float azDyn = medianReady ? medianOfN(medianBufZ) : (az - gravOffZ - tempComp);
    float ayDyn = medianReady ? medianOfN(medianBufY) : (ay - gravOffY);
    float axDyn = medianReady ? medianOfN(medianBufX) : (ax - gravOffX);

    ImuSample s;
    s.az_filt   = applyLPF(azDyn, lpf_z);
    s.ay_filt   = applyLPF(ayDyn, lpf_y);
    s.ax_filt   = applyLPF(axDyn, lpf_x);
    s.az_hp     = applyHPF(s.az_filt, hpf_z_in, hpf_z_out);
    s.ay_hp     = applyHPF(s.ay_filt, hpf_y_in, hpf_y_out);
    s.roll_rate  = (gxr / 65.5f) - gyroOffX;
    s.pitch_rate = (gyr / 65.5f) - gyroOffY;
    s.yaw_rate   = (gzr / 65.5f) - gyroOffZ;
    s.temperature = lastMpuTemp;
    s.timestamp   = millis();
    return s;
}

void pushToBuffer(const ImuSample &s) {
    ringBuf[bufHead] = s;
    bufHead  = (bufHead + 1) % BUFFER_SIZE;
    if (bufCount < BUFFER_SIZE) bufCount++;
}

ImuSample bufferAt(int i) {
    return ringBuf[(bufHead - bufCount + i + BUFFER_SIZE * 2) % BUFFER_SIZE];
}

// ============================================================
//  JERK
// ============================================================
float computeJerk(float z) {
    static float prev = 0;
    if (_jerkNeedsReset) {
        prev = z;
        _jerkNeedsReset = false;
        return 0;
    }
    float jerk = (z - prev) / (SAMPLE_INTERVAL_US / 1000000.0f);
    prev = z;
    return jerk;
}

float dynamicJerkThresh(float spd) {
    float noiseRatio  = calibStdZ / CALIB_STDDEV_LIMIT;
    float noiseAdapt  = fminf(JERK_NOISE_MULT * noiseRatio, JERK_NOISE_ADAPT_CAP);
    return (BASE_JERK_THRESH + SPEED_JERK_COEFF * spd) * fmaxf(noiseAdapt, 1.0f);
}

bool isMoving(const ImuSample &s) {
    static float ema = 0;
    float lin = fabsf(s.ax_filt) + fabsf(s.ay_filt) + fabsf(s.az_filt);
    float rot = 0.03f * (fabsf(s.roll_rate) + fabsf(s.pitch_rate));
    ema = 0.92f * ema + 0.08f * (lin + rot);
    return ema >= MIN_MOTION_SCORE;
}

void updateBaseline(float z) {
    baselineRmsAccum += z * z;
    baselineSampleCount++;
    if (baselineSampleCount >= BASELINE_WINDOW) {
        float newBaseline = sqrtf(baselineRmsAccum / baselineSampleCount);
        baselineRmsZ        = 0.9f * baselineRmsZ + 0.1f * newBaseline;
        baselineRmsAccum    = 0;
        baselineSampleCount = 0;
    }
}

// ============================================================
//  DETECTION FSM
// ============================================================
void runDetectionFSM(const ImuSample &s) {
    float         effSpeed = gpsValid ? currentSpeedKmh : NO_GPS_SPEED_ASSUMED;
    float         jerk     = computeJerk(s.az_filt);
    float         dynTh    = dynamicJerkThresh(effSpeed);
    bool          moving   = gpsValid ? (currentSpeedKmh >= MIN_SPEED_KMH) : isMoving(s);
    unsigned long now      = millis();

    switch (detectState) {
        case IDLE:
            if ((now - lastTriggerMs) < DEBOUNCE_MS) break;
            if (!moving) break;
            if (fabsf(jerk) > dynTh) {
                detectState  = EVENT_CAPTURE;
                eventTimer   = EVENT_CAPTURE_TICKS;
                eventStartMs = now;
                Serial.printf("[TRIG] Jerk=%.1f (th=%.1f) @ %.1fkm/h base=%.3f\n",
                              jerk, dynTh, effSpeed, baselineRmsZ);
            }
            break;

        case EVENT_CAPTURE:
            if (--eventTimer <= 0) detectState = CLASSIFYING;
            break;

        case CLASSIFYING: {
            int    n    = EVENT_CAPTURE_TICKS;
            if (n > bufCount) n = bufCount;
            float  conf = 0;
            String type = classifyAnomaly(n, conf);

            if (type == "Pothole") {
                int   si   = bufCount - n;
                float maxZ = 0;
                for (int i = si; i < bufCount; i++) {
                    float v = fabsf(bufferAt(i).az_filt);
                    if (v > maxZ) maxZ = v;
                }
                float  rmsZ = computeRMS(si, n, 0);
                float  rmsY = computeRMS(si, n, 1);
                String sev  = classifySeverity(maxZ, rmsZ, rmsY);
                lastTriggerMs = now;

                float lat = gps.location.isValid() ? gps.location.lat() : FALLBACK_LAT;
                float lng = gps.location.isValid() ? gps.location.lng() : FALLBACK_LNG;

                if (isDuplicateLocation(lat, lng)) {
                    Serial.printf("[DEDUP] <%.0fm from recent — skipped\n", GPS_DEDUP_RADIUS_M);
                } else {
                    addToDedupRing(lat, lng);
                    handleConfirmedEvent(type, sev, maxZ / 9.81f, conf);
                }
            } else {
                rejectCount++;
                Serial.printf("[SKIP] %s (%.0f%%) reject#%d\n",
                              type.c_str(), conf * 100, rejectCount);
            }
            detectState = IDLE;
            break;
        }
    }
}

// ============================================================
//  CLASSIFICATION
// ============================================================
String classifyAnomaly(int n, float &outConf) {
    outConf = 0;
    if (bufCount < 15) return "Insufficient";
    if (n < 15)        n = 15;
    if (n > bufCount)  n = bufCount;
    int si = bufCount - n;

    ImuSample first = bufferAt(si);
    float maxZ = first.az_filt, minZ = first.az_filt;
    float maxY = fabsf(first.ay_filt), maxX = fabsf(first.ax_filt);
    float peakRoll  = fabsf(first.roll_rate);
    float peakPitch = fabsf(first.pitch_rate);
    float maxYaw    = fabsf(first.yaw_rate);
    float sumX = 0, sumZ = 0;
    int   dipSpike = 0, zeroCross = 0;
    float prevZ = first.az_filt;

    for (int i = si; i < bufCount; i++) {
        ImuSample s = bufferAt(i);
        if (s.az_filt > maxZ) maxZ = s.az_filt;
        if (s.az_filt < minZ) minZ = s.az_filt;
        if (fabsf(s.ay_filt)   > maxY)      maxY      = fabsf(s.ay_filt);
        if (fabsf(s.ax_filt)   > maxX)      maxX      = fabsf(s.ax_filt);
        if (fabsf(s.roll_rate) > peakRoll)  peakRoll  = fabsf(s.roll_rate);
        if (fabsf(s.pitch_rate)> peakPitch) peakPitch = fabsf(s.pitch_rate);
        if (fabsf(s.yaw_rate)  > maxYaw)    maxYaw    = fabsf(s.yaw_rate);
        sumX += s.ax_filt;
        sumZ += s.az_filt;

        if (prevZ < -1.5f && s.az_filt > 1.5f) dipSpike++;
        if ((prevZ < 0 && s.az_filt >= 0) || (prevZ >= 0 && s.az_filt < 0)) zeroCross++;
        prevZ = s.az_filt;
    }

    float avgX     = sumX / n;
    float impactZ  = fmaxf(fabsf(maxZ), fabsf(minZ));
    float zyRatio  = impactZ / (maxY + 0.001f);
    float rmsZ     = computeRMS(si, n, 0);
    float crest    = computeCrestFactor(impactZ, rmsZ);
    float energy   = computeEnergy(si, n);
    float entropy  = computeSpectralEntropy(si, n);
    float snrZ     = rmsZ / (baselineRmsZ + 0.001f);

    Serial.println(F("  [FEAT] ════════════════════════════════════"));
    Serial.printf("    Z: pk=%.2f min=%.2f rms=%.2f | Y: pk=%.2f | X: avg=%.2f\n",
                  maxZ, minZ, rmsZ, maxY, avgX);
    Serial.printf("    Z/Y=%.2f Crest=%.1f Energy=%.2f Entropy=%.2f SNR=%.1f\n",
                  zyRatio, crest, energy, entropy, snrZ);
    Serial.printf("    Roll=%.1f Pitch=%.1f Yaw=%.1f | dip=%d zc=%d\n",
                  peakRoll, peakPitch, maxYaw, dipSpike, zeroCross);

    if (avgX < -BRAKE_X_THRESH && dipSpike == 0 && maxY < 2.5f) {
        outConf = CONFIDENCE_HIGH;
        Serial.println(F("  [CLASS] → Braking"));
        return "Braking";
    }

    if (peakPitch > PITCH_THRESH && zyRatio > ZY_RATIO_LIMIT &&
        peakRoll < ROLL_THRESH * 0.4f) {
        outConf = CONFIDENCE_HIGH;
        Serial.println(F("  [CLASS] → SpeedBreaker"));
        return "SpeedBreaker";
    }

    if (maxYaw > YAW_TURN_THRESH && peakRoll < ROLL_THRESH * 0.3f &&
        impactZ < MODERATE_MS2 * 0.4f) {
        outConf = CONFIDENCE_MED;
        Serial.println(F("  [CLASS] → Turning"));
        return "Turning";
    }

    if (entropy > 0.92f && crest < 2.0f && dipSpike == 0) {
        outConf = CONFIDENCE_MED;
        Serial.println(F("  [CLASS] → ContinuousVibration"));
        return "Vibration";
    }

    float score = 0;

    if      (peakRoll > ROLL_THRESH)             score += 0.25f;
    else if (peakRoll > ROLL_THRESH * 0.5f)      score += 0.12f;

    if      (zyRatio < ZY_RATIO_LIMIT)           score += 0.18f;
    else if (zyRatio < ZY_RATIO_LIMIT * 1.4f)    score += 0.07f;

    if (dipSpike > 0) score += 0.22f;
    if (dipSpike > 1) score += 0.05f;

    if      (crest > 4.5f)  score += 0.10f;
    else if (crest > 2.5f)  score += 0.05f;

    if      (energy > 5.0f) score += 0.08f;
    else if (energy > 2.0f) score += 0.04f;

    if (zeroCross >= 2 && zeroCross <= 8) score += 0.04f;

    if      (snrZ > 3.0f)  score += 0.06f;
    else if (snrZ > 1.5f)  score += 0.02f;

    if (entropy < 0.7f && crest > 3.0f) score += 0.04f;

    Serial.printf("  [SCORE] %.0f%%\n", score * 100);

    if (score >= MIN_POTHOLE_SCORE) {
        outConf = score;
        Serial.println(F("  [CLASS] → POTHOLE ✓"));
        return "Pothole";
    }

    if (score >= BORDERLINE_SCORE && impactZ > MODERATE_MS2) {
        outConf = score;
        Serial.println(F("  [CLASS] → POTHOLE (high-impact override) ✓"));
        return "Pothole";
    }

    outConf = 1.0f - score;
    Serial.printf("  [CLASS] → Vibration (%.0f%% < %.0f%%)\n",
                  score * 100, MIN_POTHOLE_SCORE * 100);
    return "Vibration";
}

String classifySeverity(float peakZ, float rmsZ, float rmsY) {
    float combinedRms = sqrtf(rmsZ * rmsZ + rmsY * rmsY * 0.5f);

    if (peakZ >= SEVERE_MS2)   return "Severe";
    if (peakZ >= MODERATE_MS2) return "Moderate";
    if (combinedRms > 12.0f && peakZ > MODERATE_MS2 * 0.6f) return "Moderate";
    return "Minor";
}

// ============================================================
//  SIGNAL ANALYSIS
// ============================================================
float computeRMS(int start, int count, int axis) {
    float sum = 0;
    for (int i = start; i < start + count; i++) {
        ImuSample s = bufferAt(i);
        float v = (axis == 0) ? s.az_hp : s.ay_hp;
        sum += v * v;
    }
    return sqrtf(sum / count);
}

float computeCrestFactor(float peak, float rms) {
    return (rms < 0.01f) ? 0 : peak / rms;
}

float computeEnergy(int start, int count) {
    float e  = 0;
    float dt = SAMPLE_INTERVAL_US / 1000000.0f;
    for (int i = start; i < start + count; i++) {
        float v = bufferAt(i).az_hp;
        e += v * v * dt;
    }
    return e;
}

float computeSpectralEntropy(int start, int count) {
    const int BINS   = 4;
    float binEnergy[BINS] = {0};
    int   perBin    = count / BINS;
    if (perBin < 2) return 0;

    float totalE = 0;
    for (int b = 0; b < BINS; b++) {
        for (int i = 0; i < perBin; i++) {
            float v = bufferAt(start + b * perBin + i).az_hp;
            binEnergy[b] += v * v;
        }
        totalE += binEnergy[b];
    }
    if (totalE < 0.001f) return 0;

    float entropy = 0;
    for (int b = 0; b < BINS; b++) {
        float p = binEnergy[b] / totalE;
        if (p > 0.001f) entropy -= p * log2f(p);
    }
    return entropy / log2f(BINS);
}

// ============================================================
//  GEOSPATIAL
// ============================================================
float haversineM(float lat1, float lng1, float lat2, float lng2) {
    const float R = 6371000.0f;
    float dLat = radians(lat2 - lat1);
    float dLng = radians(lng2 - lng1);
    float a = sinf(dLat / 2) * sinf(dLat / 2) +
              cosf(radians(lat1)) * cosf(radians(lat2)) *
              sinf(dLng / 2) * sinf(dLng / 2);
    return R * 2.0f * atan2f(sqrtf(a), sqrtf(1.0f - a));
}

bool isDuplicateLocation(float lat, float lng) {
    for (int i = 0; i < dedupCount; i++) {
        int idx = (dedupIdx - 1 - i + DEDUP_RING_SIZE * 2) % DEDUP_RING_SIZE;
        if ((millis() - dedupRing[idx].ms) > 60000UL) continue;
        if (haversineM(lat, lng, dedupRing[idx].lat, dedupRing[idx].lng) < GPS_DEDUP_RADIUS_M) {
            return true;
        }
    }
    return false;
}

void addToDedupRing(float lat, float lng) {
    dedupRing[dedupIdx] = {lat, lng, millis()};
    dedupIdx  = (dedupIdx + 1) % DEDUP_RING_SIZE;
    if (dedupCount < DEDUP_RING_SIZE) dedupCount++;
}

// ============================================================
//  EVENT HANDLING
// ============================================================
void handleConfirmedEvent(const String &type, const String &sev,
                          float gForce, float conf) {
    reportCount++;
    uint64_t ts = currentUnixMillis();

    float lat = FALLBACK_LAT, lng = FALLBACK_LNG;

    if (gps.location.isValid()) {
        lat = gps.location.lat();
        lng = gps.location.lng();
    } else {
        Serial.println(F("[GPS]  No fix — using fallback coords (Mumbai centre)"));
    }

    printEvent(type, sev, gForce, lat, lng, conf);
    startBuzzAlert(sev);   // BUGFIX-3: non-blocking

    if (WiFi.status() == WL_CONNECTED) {
        sendToFirebase(lat, lng, type, sev, gForce, conf, ts);
        currentLedMode = LED_SOLID;
    } else {
        offlineEventCount++;
        Serial.printf("[WIFI] Offline — buffering event #%d to SPIFFS\n",
                      offlineEventCount);
        bufferToSPIFFS(lat, lng, type, sev, gForce, ts);
        currentLedMode = LED_FAST_BLINK;
    }
}

void printEvent(const String &type, const String &sev, float gForce,
                float lat, float lng, float conf) {
    Serial.println(F("  ╔══════════════════════════════════════╗"));
    Serial.printf ("  ║  POTHOLE #%-4d            v%-7s ║\n",
                   reportCount % 10000, FIRMWARE_VERSION);
    Serial.println(F("  ╠══════════════════════════════════════╣"));
    Serial.printf ("  ║  Severity  : %-8s                ║\n", sev.c_str());
    Serial.printf ("  ║  G-Force   : %-6.2fg               ║\n", gForce);
    Serial.printf ("  ║  Confidence: %-3.0f%%                  ║\n", conf * 100);
    Serial.printf ("  ║  Speed     : %-5.1f km/h             ║\n", currentSpeedKmh);
    Serial.printf ("  ║  GPS       : %8.4f, %8.4f    ║\n", lat, lng);
    Serial.printf ("  ║  Sats:%-2d HDOP:%-4.1f Batt:%-4.1fV     ║\n",
                   currentSatCount, currentHdop, batteryVoltage);
    Serial.println(F("  ╚══════════════════════════════════════╝"));
}

// ============================================================
//  FIREBASE
//  BUGFIX-5: path uses deviceId + currentUnixMillis() so it
//            never collides across reboots
// ============================================================
void sendToFirebase(float lat, float lng, const String &type,
                    const String &sev, float gForce, float conf,
                    uint64_t ts) {
    uint64_t effectiveTs = (ts > 0) ? ts : currentUnixMillis();

    // BUGFIX-5: deviceId prefix + epoch timestamp — unique across reboots
    String path = "/potholes/" + deviceId + "_" + String((unsigned long long)effectiveTs)
                  + "_" + String(reportCount);

    FirebaseJson json;
    json.set("lat",            lat);
    json.set("lng",            lng);
    json.set("type",           type);
    json.set("severity",       sev);
    json.set("g_force",        gForce);
    json.set("confidence",     conf);
    json.set("speed_kmh",      currentSpeedKmh);
    json.set("heading",        currentHeading);
    json.set("satellites",     currentSatCount);
    json.set("hdop",           currentHdop);
    json.set("device_id",      deviceId);
    json.set("firmware",       FIRMWARE_VERSION);
    json.set("timestamp_ms",   (double)effectiveTs);
    json.set("device_uptime_ms",(double)millis());
    json.set("confirmed",      false);
    json.set("pass_count",     1);
    json.set("gps_valid",      gpsValid);
    json.set("battery_v",      batteryVoltage);
    json.set("mpu_temp_c",     lastMpuTemp);
    json.set("baseline_rms",   baselineRmsZ);

    if (Firebase.setJSON(fbData, path, json)) {
        Serial.println("[FB]   OK → " + path);
    } else {
        Serial.println("[FB]   FAIL: " + fbData.errorReason());
        bufferToSPIFFS(lat, lng, type, sev, gForce, effectiveTs);
    }
}

// ============================================================
//  SPIFFS BUFFERING
// ============================================================
void bufferToSPIFFS(float lat, float lng, const String &type,
                    const String &sev, float gForce, uint64_t ts) {
    if (spiffsBufferCount >= SPIFFS_MAX_BUFFER) {
        Serial.printf("[SPIFFS] Buffer full (%d) — rotating %d oldest lines\n",
                      SPIFFS_MAX_BUFFER, SPIFFS_ROTATE_LINES);
        rotateSPIFFS(SPIFFS_ROTATE_LINES);
    }

    File f = SPIFFS.open("/buffer.csv", FILE_APPEND);
    if (!f) {
        Serial.println(F("[SPIFFS] Write failed — file open error"));
        return;
    }
    f.printf("%.6f,%.6f,%s,%s,%.3f,%.0f\n",
             lat, lng, type.c_str(), sev.c_str(), gForce, (double)ts);
    f.close();
    spiffsBufferCount++;
    Serial.printf("[SPIFFS] Buffered (%d/%d)\n", spiffsBufferCount, SPIFFS_MAX_BUFFER);
}

void rotateSPIFFS(int linesToDrop) {
    File src = SPIFFS.open("/buffer.csv", FILE_READ);
    if (!src) return;

    File dst = SPIFFS.open("/buffer_tmp.csv", FILE_WRITE);
    if (!dst) { src.close(); return; }

    int skipped = 0;
    while (src.available()) {
        String line = src.readStringUntil('\n');
        line.trim();
        if (line.length() < 5) continue;
        if (skipped < linesToDrop) { skipped++; continue; }
        dst.println(line);
    }
    src.close();
    dst.close();

    SPIFFS.remove("/buffer.csv");
    SPIFFS.rename("/buffer_tmp.csv", "/buffer.csv");
    spiffsBufferCount = max(0, spiffsBufferCount - linesToDrop);
    Serial.printf("[SPIFFS] Rotated %d lines, %d remaining\n", skipped, spiffsBufferCount);
}

// ============================================================
//  SPIFFS UPLOAD
//  BUGFIX-2: on partial failure, rewrite the file keeping only
//            the lines that failed — prevents duplicate uploads
// ============================================================
void uploadBuffered() {
    if (!SPIFFS.exists("/buffer.csv")) return;
    Serial.println(F("[SPIFFS] Uploading buffered events..."));
    File f = SPIFFS.open("/buffer.csv", FILE_READ);
    if (!f) return;

    std::vector<String> lines;
    while (f.available()) {
        String line = f.readStringUntil('\n');
        line.trim();
        if (line.length() >= 5) lines.push_back(line);
    }
    f.close();

    int ok = 0, fail = 0;
    std::vector<String> failedLines;  // BUGFIX-2: track which lines failed

    for (auto &line : lines) {
        esp_task_wdt_reset();

        int c1 = line.indexOf(',');
        int c2 = line.indexOf(',', c1 + 1);
        int c3 = line.indexOf(',', c2 + 1);
        int c4 = line.indexOf(',', c3 + 1);
        int c5 = line.indexOf(',', c4 + 1);
        if (c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0) {
            // Malformed line — drop it silently
            fail++;
            continue;
        }

        float  lat  = line.substring(0, c1).toFloat();
        float  lng  = line.substring(c1 + 1, c2).toFloat();
        String type = line.substring(c2 + 1, c3);
        String sev  = line.substring(c3 + 1, c4);
        float  gf   = (c5 >= 0) ? line.substring(c4 + 1, c5).toFloat()
                                 : line.substring(c4 + 1).toFloat();
        uint64_t ts = (c5 >= 0) ? (uint64_t)line.substring(c5 + 1).toDouble() : 0;

        if (WiFi.status() != WL_CONNECTED) {
            failedLines.push_back(line);  // BUGFIX-2
            fail++;
            continue;
        }

        // BUGFIX-5: same collision-safe path scheme as sendToFirebase
        uint64_t effectiveTs = (ts > 0) ? ts : currentUnixMillis();
        String path = "/potholes/" + deviceId + "_buf_"
                      + String((unsigned long long)effectiveTs)
                      + "_" + String(reportCount++);

        FirebaseJson json;
        json.set("lat",           lat);
        json.set("lng",           lng);
        json.set("type",          type);
        json.set("severity",      sev);
        json.set("g_force",       gf);
        json.set("confidence",    0.5);
        json.set("device_id",     deviceId);
        json.set("firmware",      FIRMWARE_VERSION);
        json.set("timestamp_ms",  (double)effectiveTs);
        json.set("gps_valid",     false);
        json.set("from_buffer",   true);

        if (Firebase.setJSON(fbData, path, json)) {
            ok++;
        } else {
            Serial.println("[FB]   Upload fail: " + fbData.errorReason());
            failedLines.push_back(line);  // BUGFIX-2: keep for retry
            fail++;
        }
        delay(200);
    }

    // BUGFIX-2: rewrite file with only the lines that actually failed
    SPIFFS.remove("/buffer.csv");
    if (failedLines.empty()) {
        spiffsBufferCount = 0;
        offlineEventCount = 0;
        currentLedMode    = LED_SOLID;
        Serial.printf("[SPIFFS] %d uploaded, buffer cleared — fully synced\n", ok);
    } else {
        File fw = SPIFFS.open("/buffer.csv", FILE_WRITE);
        if (fw) {
            for (auto &fl : failedLines) fw.println(fl);
            fw.close();
        }
        spiffsBufferCount = (int)failedLines.size();
        Serial.printf("[SPIFFS] %d uploaded, %d failed — kept for retry\n", ok, fail);
        currentLedMode = LED_FAST_BLINK;
    }
}

// ============================================================
//  BUZZER — BUGFIX-3: non-blocking state machine
//  Call startBuzzAlert() to arm it.
//  Call updateBuzzer() every loop tick — it uses millis(), no delay().
// ============================================================
void startBuzzAlert(const String &sev) {
    buzzSM.totalBeeps  = 1;
    buzzSM.onMs        = 100;
    buzzSM.offMs       = 80;
    if (sev == "Moderate") { buzzSM.totalBeeps = 2; buzzSM.onMs = 80; }
    if (sev == "Severe")   { buzzSM.totalBeeps = 3; buzzSM.onMs = 60; buzzSM.offMs = 50; }
    buzzSM.beepsDone   = 0;
    buzzSM.buzzerOn    = true;
    buzzSM.lastChangeMs = millis();
    buzzSM.active      = true;
    digitalWrite(BUZZER_PIN, HIGH);
}

void updateBuzzer() {
    if (!buzzSM.active) return;
    unsigned long now = millis();

    if (buzzSM.buzzerOn) {
        if ((now - buzzSM.lastChangeMs) >= (unsigned long)buzzSM.onMs) {
            digitalWrite(BUZZER_PIN, LOW);
            buzzSM.buzzerOn    = false;
            buzzSM.lastChangeMs = now;
            buzzSM.beepsDone++;
            if (buzzSM.beepsDone >= buzzSM.totalBeeps) {
                buzzSM.active = false;  // done
            }
        }
    } else {
        // waiting in off gap before next beep
        if (buzzSM.beepsDone < buzzSM.totalBeeps &&
            (now - buzzSM.lastChangeMs) >= (unsigned long)buzzSM.offMs) {
            digitalWrite(BUZZER_PIN, HIGH);
            buzzSM.buzzerOn    = true;
            buzzSM.lastChangeMs = now;
        }
    }
}

// ============================================================
//  GPS
//  BUGFIX-1: quality gate changed from || to &&
//            — with ||, HDOP=99 + sats>=4 wrongly set gpsValid=true
// ============================================================
void parseGPS() {
    while (gpsSerial.available()) gps.encode(gpsSerial.read());

    if (gps.speed.isValid() && gps.speed.isUpdated()) {
        float spd = gps.speed.kmph();
        if (spd >= 0.0f && spd <= MAX_SPEED_KMH)
            currentSpeedKmh = spd;
    }
    if (gps.course.isValid())     currentHeading  = gps.course.deg();
    if (gps.satellites.isValid()) currentSatCount = gps.satellites.value();
    if (gps.hdop.isValid())       currentHdop     = gps.hdop.hdop();

    if (gps.location.isValid() && gps.location.age() <= 2000) {
        // BUGFIX-1: was || — both conditions must pass
        if (currentHdop <= GPS_HDOP_LIMIT && currentSatCount >= GPS_MIN_SATS) {
            currentLat = gps.location.lat();
            currentLng = gps.location.lng();
            gpsValid   = true;
        }
    } else if (gps.location.age() > 3000) {
        gpsValid = false;
    }
}

// ============================================================
//  TIME / NTP
// ============================================================
bool hasValidClock() {
    return time(nullptr) >= (time_t)EPOCH_VALID_AFTER;
}

uint64_t currentUnixMillis() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    if (tv.tv_sec < (time_t)EPOCH_VALID_AFTER) return 0;
    return ((uint64_t)tv.tv_sec * 1000ULL) + ((uint64_t)tv.tv_usec / 1000ULL);
}

void syncClock() {
    if (WiFi.status() != WL_CONNECTED) return;
    if (hasValidClock()) return;
    Serial.println(F("[NTP]  Syncing..."));
    configTime(NTP_TIMEZONE_OFF, 0, "pool.ntp.org", "time.google.com", "time.nist.gov");
    for (int i = 0; i < 25; i++) {
        if (hasValidClock()) break;
        delay(200);
    }
    if (hasValidClock()) {
        Serial.printf("[NTP]  Synced (%llu ms)\n", (unsigned long long)currentUnixMillis());
    } else {
        Serial.println(F("[NTP]  Unavailable — timestamps will be 0 until synced"));
    }
}

// ============================================================
//  WIFI
// ============================================================
int scanAndPickNetwork() {
    Serial.println(F("[WIFI] Scanning..."));
    int found = WiFi.scanNetworks(false, false, false, 300);
    if (found <= 0) {
        Serial.println(F("[WIFI] No networks visible"));
        return -1;
    }

    int   bestIdx   = -1;
    int   bestRssi  = -999;
    int   bestKnown = -1;

    for (int s = 0; s < found; s++) {
        String scannedSsid = WiFi.SSID(s);
        int    rssi        = WiFi.RSSI(s);
        for (int k = 0; k < KNOWN_NETWORK_COUNT; k++) {
            if (scannedSsid == KNOWN_NETWORKS[k].ssid) {
                Serial.printf("[WIFI] Found [%d] \"%s\" RSSI=%d\n",
                              k, KNOWN_NETWORKS[k].ssid, rssi);
                bool betterRssi   = (rssi > bestRssi);
                bool samePriority = (rssi == bestRssi && k < bestKnown);
                if (bestIdx == -1 || betterRssi || samePriority) {
                    bestIdx   = s;
                    bestRssi  = rssi;
                    bestKnown = k;
                }
                break;
            }
        }
    }
    WiFi.scanDelete();
    return bestKnown;
}

void connectWiFi() {
    if (WiFi.status() == WL_CONNECTED) return;

    currentLedMode = LED_SLOW_BLINK;

    int idx = scanAndPickNetwork();
    if (idx < 0) {
        Serial.println(F("[WIFI] No known network in range — staying offline"));
        currentLedMode = LED_FAST_BLINK;
        return;
    }

    const char *ssid = KNOWN_NETWORKS[idx].ssid;
    const char *pass = KNOWN_NETWORKS[idx].pass;
    Serial.printf("[WIFI] Connecting to [%d] \"%s\"", idx, ssid);

    WiFi.begin(ssid, pass);
    for (int i = 0; i < 20 && WiFi.status() != WL_CONNECTED; i++) {
        delay(400);
        Serial.print('.');
        updateLed();
    }

    if (WiFi.status() == WL_CONNECTED) {
        Serial.printf("\n[WIFI] ✓ %s  IP:%s  RSSI:%d dBm\n",
                      ssid,
                      WiFi.localIP().toString().c_str(),
                      WiFi.RSSI());
        currentLedMode = LED_SOLID;
        syncClock();
    } else {
        Serial.printf("\n[WIFI] ✗ Could not connect to \"%s\"\n", ssid);
        currentLedMode = LED_FAST_BLINK;
    }
}

// ============================================================
//  STATUS LED
// ============================================================
void updateLed() {
    unsigned long now = millis();
    switch (currentLedMode) {
        case LED_SOLID:
            digitalWrite(STATUS_LED_PIN, HIGH);
            break;
        case LED_SLOW_BLINK:
            if (now - lastLedToggleMs >= 500) {
                lastLedToggleMs = now;
                ledState = !ledState;
                digitalWrite(STATUS_LED_PIN, ledState ? HIGH : LOW);
            }
            break;
        case LED_FAST_BLINK:
            if (now - lastLedToggleMs >= 125) {
                lastLedToggleMs = now;
                ledState = !ledState;
                digitalWrite(STATUS_LED_PIN, ledState ? HIGH : LOW);
            }
            break;
    }
}

// ============================================================
//  FIREBASE SETUP
// ============================================================
void setupFirebase() {
    fbConfig.host                        = FIREBASE_HOST;
    fbConfig.signer.tokens.legacy_token  = FIREBASE_AUTH;
    Firebase.begin(&fbConfig, &fbAuth);
    Firebase.reconnectWiFi(true);
    Serial.println(F("[FB]   Ready"));
}

// ============================================================
//  DEVICE ID
// ============================================================
void generateDeviceId() {
    uint64_t mac = ESP.getEfuseMac();
    char buf[18];
    snprintf(buf, sizeof(buf), "SX-%04X%08X",
             (uint16_t)(mac >> 32), (uint32_t)mac);
    deviceId = String(buf);
    Serial.printf("[SYS]  ID: %s\n", deviceId.c_str());
}

// ============================================================
//  BATTERY / TEMPERATURE
// ============================================================
float readBattery() {
    int raw = analogRead(BATTERY_ADC_PIN);
    return (raw / 4095.0f) * 3.3f * BATT_DIVIDER_RATIO;
}

float readMpuTemp() {
    int16_t rawTemp = mpu.getTemperature();
    lastMpuTemp = (rawTemp / 340.0f) + 36.53f;
    return lastMpuTemp;
}

// ============================================================
//  SPIFFS HEALTH CHECK
// ============================================================
void checkSpiffsHealth() {
    size_t total = SPIFFS.totalBytes();
    size_t used  = SPIFFS.usedBytes();
    float  pct   = (total > 0) ? (used * 100.0f / total) : 0;
    Serial.printf("[SPIFFS] %u/%u bytes (%.0f%%)\n", used, total, pct);
    if (pct > 90.0f) {
        Serial.println(F("[SPIFFS] >90% full — rotating buffer"));
        rotateSPIFFS(SPIFFS_ROTATE_LINES);
    }
}

// ============================================================
//  DIAGNOSTIC OUTPUT
// ============================================================
void printBanner() {
    Serial.println(F("\n╔════════════════════════════════════════════╗"));
    Serial.println(F("║   SusX Pothole Detection System  v4.3     ║"));
    Serial.println(F("║   Industry-Grade Multi-Axis Pipeline      ║"));
    Serial.println(F("║   Median+LPF+HPF | Spectral | Adaptive   ║"));
    Serial.println(F("╚════════════════════════════════════════════╝\n"));
}

void printConfig() {
    Serial.println(F("\n  ┌─────────────────────────┬────────────────┐"));
    Serial.println(F("  │ Parameter               │ Value          │"));
    Serial.println(F("  ├─────────────────────────┼────────────────┤"));
    Serial.printf ("  │ Firmware                │ %-14s │\n", FIRMWARE_VERSION);
    Serial.printf ("  │ Device ID               │ %-14s │\n", deviceId.c_str());
    Serial.printf ("  │ Sample Rate             │ %d Hz           │\n", SAMPLE_RATE_HZ);
    Serial.printf ("  │ Buffer Size             │ %d             │\n", BUFFER_SIZE);
    Serial.printf ("  │ Jerk Base/Coeff         │ %.1f / %.3f     │\n", BASE_JERK_THRESH, SPEED_JERK_COEFF);
    Serial.printf ("  │ Noise Adapt Cap         │ %.1f            │\n", JERK_NOISE_ADAPT_CAP);
    Serial.printf ("  │ Capture Ticks/Ms        │ %d / %dms       │\n",
                   EVENT_CAPTURE_TICKS, EVENT_CAPTURE_TICKS * (SAMPLE_INTERVAL_US / 1000));
    Serial.printf ("  │ Roll/Pitch Thresh       │ %.0f / %.0f °/s   │\n", ROLL_THRESH, PITCH_THRESH);
    Serial.printf ("  │ Severity Mod/Sev        │ %.0f / %.0f m/s²  │\n", MODERATE_MS2, SEVERE_MS2);
    Serial.printf ("  │ Dedup Radius            │ %.0f m           │\n", GPS_DEDUP_RADIUS_M);
    Serial.printf ("  │ SPIFFS Rotate Lines     │ %d              │\n", SPIFFS_ROTATE_LINES);
    Serial.printf ("  │ Calib σZ                │ %.4f m/s²      │\n", calibStdZ);
    Serial.printf ("  │ Battery                 │ %.2f V          │\n", batteryVoltage);
    Serial.printf ("  │ MPU Temp                │ %.1f °C         │\n", lastMpuTemp);
    Serial.printf ("  │ Known WiFi nets         │ %d configured  │\n", KNOWN_NETWORK_COUNT);
    Serial.printf ("  │ Offline buf count       │ %-14d │\n", spiffsBufferCount);
    Serial.println(F("  └─────────────────────────┴────────────────┘"));
    Serial.println(F(""));
    Serial.println(F("  [WIFI] Known networks:"));
    for (int i = 0; i < KNOWN_NETWORK_COUNT; i++) {
        Serial.printf("    [%d] \"%s\"\n", i, KNOWN_NETWORKS[i].ssid);
    }
}
