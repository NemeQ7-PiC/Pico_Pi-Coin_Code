#include <WiFi.h>
#include <HTTPClient.h>
#include <ArduinoJson.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <math.h>

// ============================================================
// PI-Coin Pico 2 W Miner V2
// Protocol: PI-Flex-v2 / scrypt N=256 r=1 p=1
// Core 1: continuous mining. Core 0: network + 20% opportunistic mining.
// Optional work_ticket support for pools whose /api/work response omits it.
// ============================================================

const char* ssid = "YOUR_WIFI_SSID_HERE";
const char* password = "YOUR_WIFI_PASSWORD_HERE";
const char* pool_url = "http://pi-coin.serv00.net:51431"; // Do not change this!
const char* wallet_address = "YOUR_PI-COIN_ADRESS_HERE";
const char* miner_name = "MINER_NAME";

static const uint32_t WORK_REFRESH_MS = 10000;
static const uint32_t HEARTBEAT_MS = 5000;
static const uint32_t WIFI_RETRY_MS = 5000;
static const uint32_t WIFI_CONNECT_TIMEOUT_MS = 12000;
static const uint32_t WATCHDOG_TIMEOUT_MS = 8000;
static const uint32_t CORE0_MINING_DUTY_PERCENT = 25; 
static const float HASHRATE_SMOOTH_ALPHA = 0.25f;     
static const uint32_t CORE1_MONITOR_INTERVAL_MS = 10000;
static const uint8_t CORE1_STALL_WINDOWS_BEFORE_REBOOT = 2;
static const uint32_t HEAP_LOG_INTERVAL_MS = 300000;
static const uint8_t HEARTBEAT_FAILURES_BEFORE_WIFI_RESET = 6;

static const uint32_t SCHEDULED_REBOOT_INTERVAL_MS = 6UL * 60UL * 60UL * 1000UL;

static const uint32_t SCHEDULED_REBOOT_SHARE_GRACE_MS = 30000UL;

bool core1_separate_stack = true;

#define SCRYPT_N 256
#define SCRYPT_R 1
#define SCRYPT_P 1

// ============================================================
// WORK / SHARE STATE
// ============================================================

struct DifficultyRule {
  uint8_t whole_nibbles;
  uint8_t next_threshold;
  bool has_fraction;
  float value;
};

struct WorkState {
  int32_t index;
  DifficultyRule share_rule;
  char previous_hash[65];
  char work_ticket[40];
};

struct ShareCandidate {
  uint64_t nonce;
  uint32_t generation;
  int32_t index;
  DifficultyRule rule;
  char previous_hash[65];
  char work_ticket[40];
  uint8_t hash[32];
};

WorkState work_slots[2];
volatile uint32_t active_work_slot = 0;
volatile uint32_t work_generation = 0;
volatile uint32_t work_valid = 0;

ShareCandidate share_candidate;
volatile uint32_t share_state = 0;

volatile uint32_t hashes_core0 = 0;
volatile uint32_t hashes_core1 = 0;

uint32_t last_heartbeat = 0;
uint32_t last_work_refresh = 0;
uint32_t last_rate_c0 = 0;
uint32_t last_rate_c1 = 0;
uint32_t last_wifi_attempt = 0;
uint32_t last_core1_progress_check = 0;
uint32_t last_core1_hashes_observed = 0;
uint32_t last_heap_log = 0;
uint8_t core1_stall_windows = 0;
uint8_t consecutive_heartbeat_failures = 0;
uint32_t boot_started_at = 0;
bool scheduled_reboot_pending = false;
uint32_t scheduled_reboot_pending_since = 0;

// ============================================================
// PER-CORE SCRYPT WORKSPACE
// ============================================================

struct SHA256_CTX {
  uint32_t h[8];
  uint8_t buf[64];
  uint64_t bits;
  uint32_t len;
  uint32_t w[64];
};

struct HmacBase {
  SHA256_CTX inner;
  SHA256_CTX outer;
};

struct HmacWork {
  SHA256_CTX inner;
  SHA256_CTX outer;
  uint8_t inner_hash[32];
};

struct ScryptWorkspace {
  // 256 x 128 bytes = 32 KiB.
  uint32_t V[SCRYPT_N * 32];
  uint32_t X[32];
  uint32_t Y[32];
  uint32_t B[32];
  uint8_t DK[32];

  HmacBase hmac_base;
  HmacWork hmac_work;
  uint8_t ctr[4];
  char payload[192];
};


ScryptWorkspace ws0;
ScryptWorkspace ws1;

// ============================================================
// SHA-256
// ============================================================

// SHA-256 round constants.
static const uint32_t SHA256_K[64] = {
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32 - n));
}

static inline uint32_t be32(const uint8_t* p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static inline uint32_t le32(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
         ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static inline void store_be32(uint8_t* p, uint32_t x) {
  p[0]=(uint8_t)(x>>24); p[1]=(uint8_t)(x>>16); p[2]=(uint8_t)(x>>8); p[3]=(uint8_t)x;
}

static void sha256_init(SHA256_CTX& c) {
  c.h[0]=0x6a09e667; c.h[1]=0xbb67ae85; c.h[2]=0x3c6ef372; c.h[3]=0xa54ff53a;
  c.h[4]=0x510e527f; c.h[5]=0x9b05688c; c.h[6]=0x1f83d9ab; c.h[7]=0x5be0cd19;
  c.bits=0; c.len=0;
}

static void sha256_transform(SHA256_CTX& c, const uint8_t* m) {
  for(int i=0;i<16;i++) c.w[i]=be32(m+i*4);
  for(int i=16;i<64;i++) {
    uint32_t s0=rotr32(c.w[i-15],7)^rotr32(c.w[i-15],18)^(c.w[i-15]>>3);
    uint32_t s1=rotr32(c.w[i-2],17)^rotr32(c.w[i-2],19)^(c.w[i-2]>>10);
    c.w[i]=c.w[i-16]+s0+c.w[i-7]+s1;
  }

  uint32_t a=c.h[0],b=c.h[1],cc=c.h[2],d=c.h[3];
  uint32_t e=c.h[4],f=c.h[5],g=c.h[6],hh=c.h[7];

  for(int i=0;i<64;i++) {
    uint32_t S1=rotr32(e,6)^rotr32(e,11)^rotr32(e,25);
    uint32_t ch=(e&f)^((~e)&g);
    uint32_t t1=hh+S1+ch+SHA256_K[i]+c.w[i];
    uint32_t S0=rotr32(a,2)^rotr32(a,13)^rotr32(a,22);
    uint32_t maj=(a&b)^(a&cc)^(b&cc);
    uint32_t t2=S0+maj;
    hh=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
  }

  c.h[0]+=a; c.h[1]+=b; c.h[2]+=cc; c.h[3]+=d;
  c.h[4]+=e; c.h[5]+=f; c.h[6]+=g; c.h[7]+=hh;
}

static void sha256_update(SHA256_CTX& c, const uint8_t* data, size_t n) {
  c.bits += (uint64_t)n*8ULL;
  while(n) {
    uint32_t take=64-c.len;
    if(take>n) take=(uint32_t)n;
    memcpy(c.buf+c.len,data,take);
    c.len+=take; data+=take; n-=take;
    if(c.len==64) { sha256_transform(c,c.buf); c.len=0; }
  }
}

static void sha256_final(SHA256_CTX& c, uint8_t out[32]) {
  uint32_t i=c.len;
  c.buf[i++]=0x80;
  if(i>56) {
    while(i<64)c.buf[i++]=0;
    sha256_transform(c,c.buf);
    i=0;
  }
  while(i<56)c.buf[i++]=0;
  for(int j=0;j<8;j++) c.buf[63-j]=(uint8_t)(c.bits>>(8*j));
  sha256_transform(c,c.buf);
  for(int j=0;j<8;j++) store_be32(out+j*4,c.h[j]);
}

// ============================================================
// HMAC / PBKDF2
// ============================================================

static void hmac_prepare(const uint8_t* key, size_t key_len, HmacBase& base) {
  uint8_t k0[64]={0};
  if(key_len>64) {
    SHA256_CTX c;
    uint8_t hashed[32];
    sha256_init(c); sha256_update(c,key,key_len); sha256_final(c,hashed);
    memcpy(k0,hashed,32);
  } else {
    memcpy(k0,key,key_len);
  }

  uint8_t ipad[64],opad[64];
  for(int i=0;i<64;i++) { ipad[i]=k0[i]^0x36; opad[i]=k0[i]^0x5c; }

  sha256_init(base.inner);
  sha256_update(base.inner,ipad,64);
  sha256_init(base.outer);
  sha256_update(base.outer,opad,64);
}

static void hmac_run_counter(const HmacBase& base,
                             const uint8_t* salt,size_t salt_len,
                             uint32_t counter,
                             HmacWork& work,
                             uint8_t out[32]) {
  work.inner=base.inner;
  sha256_update(work.inner,salt,salt_len);

  uint8_t ctr[4];
  ctr[0]=(uint8_t)(counter>>24); ctr[1]=(uint8_t)(counter>>16);
  ctr[2]=(uint8_t)(counter>>8); ctr[3]=(uint8_t)counter;
  sha256_update(work.inner,ctr,4);
  sha256_final(work.inner,work.inner_hash);

  work.outer=base.outer;
  sha256_update(work.outer,work.inner_hash,32);
  sha256_final(work.outer,out);
}

static void pbkdf2_c1(const HmacBase& base,
                      const uint8_t* salt,size_t salt_len,
                      uint8_t* out,size_t out_len,
                      HmacWork& work) {
  uint32_t blocks=(uint32_t)((out_len+31)/32);
  for(uint32_t i=1;i<=blocks;i++) {
    uint8_t u[32];
    hmac_run_counter(base,salt,salt_len,i,work,u);
    size_t offset=(size_t)(i-1)*32;
    size_t take=out_len-offset;
    if(take>32)take=32;
    memcpy(out+offset,u,take);
  }
}

// ============================================================
// Salsa20/8 + scrypt ROMix
// ============================================================

static inline uint32_t salsa_rot(uint32_t x,int b) {
  return (x<<b)|(x>>(32-b));
}

static void salsa20_8(uint32_t x[16]) {
  uint32_t z[16];
  memcpy(z,x,sizeof(z));

  for(int r=0;r<4;r++) {
    z[4]^=salsa_rot(z[0]+z[12],7); z[8]^=salsa_rot(z[4]+z[0],9);
    z[12]^=salsa_rot(z[8]+z[4],13); z[0]^=salsa_rot(z[12]+z[8],18);
    z[9]^=salsa_rot(z[5]+z[1],7); z[13]^=salsa_rot(z[9]+z[5],9);
    z[1]^=salsa_rot(z[13]+z[9],13); z[5]^=salsa_rot(z[1]+z[13],18);
    z[14]^=salsa_rot(z[10]+z[6],7); z[2]^=salsa_rot(z[14]+z[10],9);
    z[6]^=salsa_rot(z[2]+z[14],13); z[10]^=salsa_rot(z[6]+z[2],18);
    z[3]^=salsa_rot(z[15]+z[11],7); z[7]^=salsa_rot(z[3]+z[15],9);
    z[11]^=salsa_rot(z[7]+z[3],13); z[15]^=salsa_rot(z[11]+z[7],18);

    z[1]^=salsa_rot(z[0]+z[3],7); z[2]^=salsa_rot(z[1]+z[0],9);
    z[3]^=salsa_rot(z[2]+z[1],13); z[0]^=salsa_rot(z[3]+z[2],18);
    z[6]^=salsa_rot(z[5]+z[4],7); z[7]^=salsa_rot(z[6]+z[5],9);
    z[4]^=salsa_rot(z[7]+z[6],13); z[5]^=salsa_rot(z[4]+z[7],18);
    z[11]^=salsa_rot(z[10]+z[9],7); z[8]^=salsa_rot(z[11]+z[10],9);
    z[9]^=salsa_rot(z[8]+z[11],13); z[10]^=salsa_rot(z[9]+z[8],18);
    z[12]^=salsa_rot(z[15]+z[14],7); z[13]^=salsa_rot(z[12]+z[15],9);
    z[14]^=salsa_rot(z[13]+z[12],13); z[15]^=salsa_rot(z[14]+z[13],18);
  }

  for(int i=0;i<16;i++) x[i]+=z[i];
}

static void block_mix(const uint32_t in[32],uint32_t out[32]) {
  uint32_t x[16];
  memcpy(x,in+16,sizeof(x));
  for(int j=0;j<2;j++) {
    for(int k=0;k<16;k++)x[k]^=in[j*16+k];
    salsa20_8(x);
    memcpy(out+j*16,x,sizeof(x));
  }
}

static bool scrypt_hash(const uint8_t* pass,size_t pass_len,
                        const uint8_t* salt,size_t salt_len,
                        uint8_t out[32],ScryptWorkspace& ws) {
  hmac_prepare(pass,pass_len,ws.hmac_base);
  pbkdf2_c1(ws.hmac_base,salt,salt_len,(uint8_t*)ws.B,128,ws.hmac_work);

  memcpy(ws.X,ws.B,128);
  uint32_t* cur=ws.X;
  uint32_t* next=ws.Y;

  for(int i=0;i<SCRYPT_N;i++) {
    memcpy(ws.V+i*32,cur,128);
    block_mix(cur,next);
    uint32_t* t=cur;cur=next;next=t;
  }

  for(int i=0;i<SCRYPT_N;i++) {
    uint32_t j=cur[16]&(SCRYPT_N-1);
    const uint32_t* v=ws.V+j*32;
    uint32_t mixed[32];
    for(int k=0;k<32;k++)mixed[k]=cur[k]^v[k];
    block_mix(mixed,next);
    uint32_t* t=cur;cur=next;next=t;
  }

  pbkdf2_c1(ws.hmac_base,(const uint8_t*)cur,128,out,32,ws.hmac_work);
  return true;
}

// ============================================================
// PI-FLEX
// ============================================================

static bool pi_flex_hash_raw(int index,const char* previous_hash,
                             uint64_t nonce,uint8_t out[32],
                             ScryptWorkspace& ws) {
  int len=snprintf(ws.payload,sizeof(ws.payload),"%d|%s|%s|%llu",
                   index,previous_hash,wallet_address,
                   (unsigned long long)nonce);
  if(len<=0 || len>=(int)sizeof(ws.payload))return false;

  return scrypt_hash((const uint8_t*)ws.payload,(size_t)len,
                     (const uint8_t*)"PI-Flex-v2",10,out,ws);
}

static void bytes_to_hex(const uint8_t in[32],char out[65]) {
  static const char digits[]="0123456789abcdef";
  for(int i=0;i<32;i++) {
    out[i*2]=digits[in[i]>>4];
    out[i*2+1]=digits[in[i]&15];
  }
  out[64]='\0';
}

// ============================================================
// DIFFICULTY
// ============================================================

static DifficultyRule make_rule(float difficulty) {
  DifficultyRule r;
  r.value=difficulty;
  float d=difficulty;
  if(d<0)d=0;
  int whole=(int)d;
  if(whole>64)whole=64;
  r.whole_nibbles=(uint8_t)whole;
  float frac=d-(float)whole;
  r.has_fraction=(frac>0.000001f && whole<64);
  if(r.has_fraction) {
    int threshold=(int)ceilf(powf(16.0f,frac));
    if(threshold<1)threshold=1;
    if(threshold>16)threshold=16;
    r.next_threshold=(uint8_t)threshold;
  } else {
    r.next_threshold=16;
  }
  return r;
}

static bool meets_rule(const uint8_t hash[32],const DifficultyRule& r) {
  int whole=r.whole_nibbles;
  int full_bytes=whole/2;

  for(int i=0;i<full_bytes;i++) {
    if(hash[i]!=0)return false;
  }

  if(whole&1) {
    if((hash[full_bytes]>>4)!=0)return false;
    if(!r.has_fraction)return true;
    return (hash[full_bytes]&15)<r.next_threshold;
  }

  if(!r.has_fraction)return true;
  return (hash[full_bytes]>>4)<r.next_threshold;
}

// ============================================================
// WORK SNAPSHOT
// ============================================================

static bool read_work_snapshot(WorkState& out,uint32_t& generation) {
  if(__atomic_load_n(&work_valid,__ATOMIC_ACQUIRE)==0)return false;

  for(int tries=0;tries<3;tries++) {
    uint32_t slot=__atomic_load_n(&active_work_slot,__ATOMIC_ACQUIRE);
    WorkState tmp=work_slots[slot];
    uint32_t slot2=__atomic_load_n(&active_work_slot,__ATOMIC_ACQUIRE);
    if(slot!=slot2)continue;
    if(tmp.previous_hash[64]!='\0')continue;
    out=tmp;
    generation=__atomic_load_n(&work_generation,__ATOMIC_ACQUIRE);
    return true;
  }
  return false;
}

static void publish_work(int index,float difficulty,const char* previous_hash,const char* ticket) {
  uint32_t active=__atomic_load_n(&active_work_slot,__ATOMIC_ACQUIRE);
  uint32_t inactive=active^1U;

  work_slots[inactive].index=index;
  work_slots[inactive].share_rule=make_rule(difficulty);
  memcpy(work_slots[inactive].previous_hash,previous_hash,65);
  if(ticket != nullptr) {
    strncpy(work_slots[inactive].work_ticket,ticket,sizeof(work_slots[inactive].work_ticket)-1);
  } else {
    work_slots[inactive].work_ticket[0]='\0';
  }
  work_slots[inactive].work_ticket[sizeof(work_slots[inactive].work_ticket)-1]='\0';

  __atomic_thread_fence(__ATOMIC_RELEASE);
  __atomic_store_n(&active_work_slot,inactive,__ATOMIC_RELEASE);
  __atomic_add_fetch(&work_generation,1U,__ATOMIC_RELEASE);
  __atomic_store_n(&work_valid,1U,__ATOMIC_RELEASE);
}

// ============================================================
// NETWORK
// ============================================================

static String url_encode(const char* input) {
  static const char hex[] = "0123456789ABCDEF";
  String out;
  if(input == nullptr) return out;
  while(*input) {
    const uint8_t c = (uint8_t)*input++;
    const bool unreserved =
      (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
      (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~';
    if(unreserved) {
      out += (char)c;
    } else {
      out += '%';
      out += hex[(c >> 4) & 0x0F];
      out += hex[c & 0x0F];
    }
  }
  return out;
}

static bool get_work() {
  if(WiFi.status()!=WL_CONNECTED) return false;

  HTTPClient http;
  String url = String(pool_url) + "/api/work?wallet=" + String(wallet_address) +
               "&miner_name=" + url_encode(miner_name);
  http.begin(url);
  http.setTimeout(4000);
  http.addHeader("Connection","close");

  rp2040.wdt_reset();
  int code=http.GET();
  rp2040.wdt_reset();
  if(code<200 || code>=300) {
    Serial.print("[WORK] GET HTTP ");
    Serial.println(code);
    http.end();
    return false;
  }

  rp2040.wdt_reset();
  String body=http.getString();
  rp2040.wdt_reset();
  http.end();
  if(body.length()==0) {
    Serial.println("[WORK] Empty response");
    return false;
  }

  JsonDocument doc;
  DeserializationError err=deserializeJson(doc,body);
  if(err) {
    Serial.print("[WORK] JSON error: ");
    Serial.println(err.c_str());
    return false;
  }

  bool success = doc["success"] | true;
  if(!success) {
    Serial.println("[WORK] Pool replied success=false");
    return false;
  }

  int index=doc["index"].as<int>();
  String previous=doc["previous_hash"].as<String>();
  float difficulty=doc["share_difficulty"] | 5.0f;
  String ticketString=doc["work_ticket"] | "";
  const char* algorithm=doc["pow_algorithm"] | "";

  if(index<1 || previous.length()!=64 || !isfinite(difficulty) || difficulty<=0.0f) {
    Serial.println("[WORK] Rejected: invalid index/hash/difficulty");
    return false;
  }
  if(strcmp(algorithm,"PI-Flex-v2")!=0) {
    Serial.print("[WORK] Rejected algorithm: ");
    Serial.println(algorithm);
    return false;
  }

  char ticket[40];
  ticketString.toCharArray(ticket,sizeof(ticket));

  WorkState current;
  uint32_t currentGeneration=0;
  if(read_work_snapshot(current,currentGeneration) &&
     current.index==index &&
     strcmp(current.previous_hash,previous.c_str())==0 &&
     fabsf(current.share_rule.value-difficulty)<=0.000001f &&
     strcmp(current.work_ticket,ticket)==0) {
    return true;
  }

  publish_work(index,difficulty,previous.c_str(),ticket);
  Serial.print("[WORK] Accepted | index=");
  Serial.print(index);
  Serial.print(" | diff=");
  Serial.print(difficulty,2);
  Serial.print(" | algorithm=");
  Serial.print(algorithm);
  Serial.print(" | ticket=");
  Serial.println(ticket[0] ? "yes" : "not provided (optional mode)");
  return true;
}

static bool send_heartbeat(float rate) {
  if(WiFi.status()!=WL_CONNECTED)return false;

  HTTPClient http;
  http.begin(String(pool_url)+"/api/miner/heartbeat");
  http.setTimeout(3000);
  http.addHeader("Content-Type","application/json");
  http.addHeader("Connection","close");

  JsonDocument doc;
  doc["wallet"]=wallet_address;
  doc["miner_name"]=miner_name;
  doc["hashrate"]=rate;

  String body;
  serializeJson(doc,body);
  rp2040.wdt_reset();
  int code=http.POST(body);
  rp2040.wdt_reset();
  http.end();
  return code>=200 && code<300;
}

static bool submit_share(const ShareCandidate& candidate,const char* hash_hex) {
  HTTPClient http;
  http.begin(String(pool_url)+"/api/share");
  http.setTimeout(5000);
  http.addHeader("Content-Type","application/json");
  http.addHeader("Connection","close");

  JsonDocument doc;
  doc["wallet"]=wallet_address;
  doc["miner_name"]=miner_name;
  doc["index"]=candidate.index;
  doc["previous_hash"]=candidate.previous_hash;
  doc["nonce"]=candidate.nonce;
  doc["hash"]=hash_hex;
  doc["pow_algorithm"]="PI-Flex-v2";
  if(candidate.work_ticket[0] != '\0') {
    doc["work_ticket"] = candidate.work_ticket;
  }

  String body;
  serializeJson(doc,body);
  rp2040.wdt_reset();
  int code=http.POST(body);
  rp2040.wdt_reset();
  String response=http.getString();
  rp2040.wdt_reset();
  http.end();

  Serial.print("[SHARE] HTTP ");
  Serial.println(code);
  if(response.length())Serial.println(response);
  return code>=200 && code<300;
}

static bool connect_wifi() {
  if(WiFi.status()==WL_CONNECTED)return true;

  Serial.print("[WIFI] Connecting");
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid,password);

  uint32_t start=millis();
  while(WiFi.status()!=WL_CONNECTED && (uint32_t)(millis()-start)<WIFI_CONNECT_TIMEOUT_MS) {
    rp2040.wdt_reset();
    delay(150);
    Serial.print(".");
  }

  if(WiFi.status()==WL_CONNECTED) {
    Serial.println(" connected");
    Serial.print("[WIFI] IP: ");
    Serial.println(WiFi.localIP());
    return true;
  }

  Serial.println(" timeout");
  return false;
}

static void force_wifi_reconnect() {
  Serial.println("[WIFI] Reinitializing Wi-Fi after repeated heartbeat failures");
  rp2040.wdt_reset();
  WiFi.disconnect();
  delay(250);
  WiFi.mode(WIFI_OFF);
  delay(250);
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

  uint32_t start = millis();
  while(WiFi.status()!=WL_CONNECTED && (uint32_t)(millis()-start)<WIFI_CONNECT_TIMEOUT_MS) {
    rp2040.wdt_reset();
    delay(150);
  }

  if(WiFi.status()==WL_CONNECTED) {
    Serial.print("[WIFI] Reconnected; IP: ");
    Serial.println(WiFi.localIP());
  } else {
    Serial.println("[WIFI] Reconnect timed out; regular retry remains enabled");
  }
  last_wifi_attempt = millis();
}

// ============================================================
// SHARE PRE-CHECK
// ============================================================

static bool try_submit_share() {
  uint32_t ready=__atomic_load_n(&share_state,__ATOMIC_ACQUIRE);
  if(ready!=1)return false;

  if(WiFi.status()!=WL_CONNECTED)return false;

  ShareCandidate candidate=share_candidate;
  __atomic_store_n(&share_state,0U,__ATOMIC_RELEASE);

  WorkState current;
  uint32_t generation=0;
  if(!read_work_snapshot(current,generation)) {
    Serial.println("[SHARE] Pre-check failed: no valid work - NOT sending");
    return false;
  }

  if(candidate.generation!=generation ||
     candidate.index!=current.index ||
     strcmp(candidate.previous_hash,current.previous_hash)!=0 ||
     fabsf(candidate.rule.value-current.share_rule.value)>0.000001f) {
    Serial.println("[SHARE] Pre-check failed: work changed - NOT sending");
    return false;
  }

  if(!meets_rule(candidate.hash,candidate.rule)) {
    Serial.println("[SHARE] Pre-check failed: difficulty - NOT sending");
    return false;
  }

  if(!get_work()) {
    Serial.println("[SHARE] Pre-check failed: cannot refresh work - NOT sending");
    return false;
  }

  WorkState fresh;
  uint32_t fresh_generation=0;
  if(!read_work_snapshot(fresh,fresh_generation)) {
    Serial.println("[SHARE] Pre-check failed: invalid refreshed work - NOT sending");
    return false;
  }

  if(fresh.index!=candidate.index ||
     strcmp(fresh.previous_hash,candidate.previous_hash)!=0 ||
     fabsf(fresh.share_rule.value-candidate.rule.value)>0.000001f) {
    Serial.println("[SHARE] Pre-check failed: fresh work changed - NOT sending");
    return false;
  }


  uint8_t verify_hash[32];
  ScryptWorkspace& verify_ws=ws0;
  if(!pi_flex_hash_raw(candidate.index,candidate.previous_hash,candidate.nonce,verify_hash,verify_ws)) {
    Serial.println("[SHARE] Pre-check failed: recompute error - NOT sending");
    return false;
  }

  if(memcmp(verify_hash,candidate.hash,32)!=0) {
    Serial.println("[SHARE] Pre-check failed: hash mismatch - NOT sending");
    return false;
  }

  if(!meets_rule(verify_hash,fresh.share_rule)) {
    Serial.println("[SHARE] Pre-check failed: fresh difficulty - NOT sending");
    return false;
  }

  char hex[65];
  bytes_to_hex(verify_hash,hex);

  Serial.print("[SHARE] Pre-check OK | nonce=");
  Serial.print((unsigned long long)candidate.nonce);
  Serial.print(" diff=");
  Serial.println(fresh.share_rule.value,2);

  Serial.print("[SHARE] Sending nonce=");
  Serial.println((unsigned long long)candidate.nonce);

  bool ok=submit_share(candidate,hex);
  Serial.println(ok ? "[POOL] SHARE ACCEPTED" : "[POOL] SHARE REJECTED");
  return ok;
}

// ============================================================
// SHARE FINDER
// ============================================================

static void publish_share(uint64_t nonce,const WorkState& work,uint32_t generation,const uint8_t hash[32]) {
  uint32_t expected=0;
  if(!__atomic_compare_exchange_n(&share_state,&expected,2U,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))return;

  share_candidate.nonce=nonce;
  share_candidate.generation=generation;
  share_candidate.index=work.index;
  share_candidate.rule=work.share_rule;
  memcpy(share_candidate.previous_hash,work.previous_hash,65);
  memcpy(share_candidate.work_ticket,work.work_ticket,sizeof(share_candidate.work_ticket));
  memcpy(share_candidate.hash,hash,32);

  __atomic_thread_fence(__ATOMIC_RELEASE);
  __atomic_store_n(&share_state,1U,__ATOMIC_RELEASE);
  digitalWrite(LED_BUILTIN,HIGH);
}

// ============================================================
// SETUP / CORE 0
// ============================================================

void setup() {
  Serial.begin(115200);
  delay(1000);
  pinMode(LED_BUILTIN,OUTPUT);
  digitalWrite(LED_BUILTIN,LOW);

  set_sys_clock_khz(150000,true);
  rp2040.wdt_begin(WATCHDOG_TIMEOUT_MS);

  connect_wifi();
  get_work();

  last_work_refresh=millis();
  last_heartbeat=millis();
  last_wifi_attempt=millis();
  last_core1_progress_check=millis();
  last_core1_hashes_observed=__atomic_load_n(&hashes_core1,__ATOMIC_RELAXED);
  last_heap_log=millis();
  boot_started_at=millis();
  Serial.println("[SYSTEM] Scheduled full reboot enabled: every 6 hours");
}

void loop() {
  rp2040.wdt_reset();
  uint32_t now=millis();

  static uint32_t led_last=0;
  static bool led_state=false;
  if(__atomic_load_n(&work_valid,__ATOMIC_ACQUIRE)==0) {
    if((uint32_t)(now-led_last)>=150) {
      led_last=now;
      led_state=!led_state;
      digitalWrite(LED_BUILTIN,led_state?HIGH:LOW);
    }
  } else {
    digitalWrite(LED_BUILTIN,HIGH);
  }

  if(WiFi.status()!=WL_CONNECTED) {
    if((uint32_t)(now-last_wifi_attempt)>=WIFI_RETRY_MS) {
      last_wifi_attempt=now;
      connect_wifi();
    }
  }

  static uint32_t local_generation=0;
  static uint64_t nonce0=0;
  static uint32_t next_core0_hash_us=0;

  WorkState work;
  uint32_t generation=0;
  if(read_work_snapshot(work,generation)) {
    if(local_generation!=generation) {
      local_generation=generation;
      nonce0=((uint64_t)micros()<<20)^0xC0DEC0DEULL^((uint64_t)generation<<8);
      next_core0_hash_us=micros();
    }

    uint32_t hash_start=micros();
    if((int32_t)(hash_start-next_core0_hash_us)>=0) {
      uint8_t hash[32];
      uint64_t nonce=nonce0++;
      if(pi_flex_hash_raw(work.index,work.previous_hash,nonce,hash,ws0)) {
        __atomic_add_fetch(&hashes_core0,1U,__ATOMIC_RELAXED);
        if(__atomic_load_n(&work_generation,__ATOMIC_ACQUIRE)==generation && meets_rule(hash,work.share_rule)) {
          publish_share(nonce,work,generation,hash);
        }
      }
      uint32_t hash_end=micros();
      uint32_t compute_us=(uint32_t)(hash_end-hash_start);
      if(compute_us<1) compute_us=1;
      uint32_t off_us=(compute_us*(100U-CORE0_MINING_DUTY_PERCENT))/CORE0_MINING_DUTY_PERCENT;
      next_core0_hash_us=hash_end+off_us;
    }
  }

  now=millis();
  if((uint32_t)(now-last_work_refresh)>=WORK_REFRESH_MS) {
    last_work_refresh=now;
    get_work();
  }

  if(__atomic_load_n(&share_state,__ATOMIC_ACQUIRE)==1) {
    try_submit_share();
  }

  now=millis();
  if((uint32_t)(now-last_core1_progress_check)>=CORE1_MONITOR_INTERVAL_MS) {
    last_core1_progress_check=now;
    uint32_t current_core1_hashes=__atomic_load_n(&hashes_core1,__ATOMIC_RELAXED);
    if(__atomic_load_n(&work_valid,__ATOMIC_ACQUIRE)!=0 && current_core1_hashes==last_core1_hashes_observed) {
      if(core1_stall_windows<255) core1_stall_windows++;
    } else {
      core1_stall_windows=0;
    }
    last_core1_hashes_observed=current_core1_hashes;
    if(__atomic_load_n(&work_valid,__ATOMIC_ACQUIRE)!=0 && core1_stall_windows>=CORE1_STALL_WINDOWS_BEFORE_REBOOT) {
      Serial.println("[RECOVERY] Core 1 made no hashes for ~20 seconds; rebooting Pico");
      rp2040.reboot();
    }
  }


  if((uint32_t)(now-last_heap_log)>=HEAP_LOG_INTERVAL_MS) {
    last_heap_log=now;
    Serial.print("[HEAP] free=");
    Serial.print(rp2040.getFreeHeap());
    Serial.print(" bytes | used=");
    Serial.print(rp2040.getUsedHeap());
    Serial.println(" bytes");
  }


  now=millis();
  if((uint32_t)(now-last_heartbeat)>=HEARTBEAT_MS) {
    uint32_t c0=__atomic_load_n(&hashes_core0,__ATOMIC_RELAXED);
    uint32_t c1=__atomic_load_n(&hashes_core1,__ATOMIC_RELAXED);
    uint32_t d0=c0-last_rate_c0;
    uint32_t d1=c1-last_rate_c1;
    last_rate_c0=c0;
    last_rate_c1=c1;

    now=millis();
    float elapsed=(float)(now-last_heartbeat)/1000.0f;
    float raw_rate=elapsed>0.0f ? ((float)d0+(float)d1)/elapsed : 0.0f;

    last_heartbeat=now;

    
    static bool rate_initialized=false;
    static float smoothed_rate=0.0f;
    if(!rate_initialized) {
      smoothed_rate=raw_rate;
      rate_initialized=true;
    } else {
      smoothed_rate=(HASHRATE_SMOOTH_ALPHA*raw_rate)+((1.0f-HASHRATE_SMOOTH_ALPHA)*smoothed_rate);
    }

    if(send_heartbeat(smoothed_rate)) {
      consecutive_heartbeat_failures=0;
          Serial.print("[POOL] H/s raw=");
      Serial.print(raw_rate,2);
      Serial.print(" | smoothed=");
      Serial.print(smoothed_rate,2);
      Serial.print(" | Core0=");
      Serial.print(elapsed>0.0f?(float)d0/elapsed:0.0f,2);
      Serial.print(" | Core1=");
      Serial.println(elapsed>0.0f?(float)d1/elapsed:0.0f,2);
    } else {
      Serial.println("[POOL] Heartbeat failed");
      if(consecutive_heartbeat_failures<255) consecutive_heartbeat_failures++;
      if(consecutive_heartbeat_failures>=HEARTBEAT_FAILURES_BEFORE_WIFI_RESET) {
        consecutive_heartbeat_failures=0;
        if(WiFi.status()==WL_CONNECTED) {
          force_wifi_reconnect();
        } else {
          Serial.println("[WIFI] Disconnected; normal reconnect loop will retry");
        }
      }
    }

  }
  now=millis();
  if(!scheduled_reboot_pending &&
     (uint32_t)(now-boot_started_at)>=SCHEDULED_REBOOT_INTERVAL_MS) {
    scheduled_reboot_pending=true;
    scheduled_reboot_pending_since=now;
    Serial.println("[SYSTEM] 6-hour uptime reached; preparing scheduled reboot");
  }

  if(scheduled_reboot_pending) {
    uint32_t pending_state=__atomic_load_n(&share_state,__ATOMIC_ACQUIRE);
    bool grace_expired=(uint32_t)(now-scheduled_reboot_pending_since)>=SCHEDULED_REBOOT_SHARE_GRACE_MS;
    if(pending_state==0 || grace_expired) {
      if(pending_state!=0) {
        Serial.println("[SYSTEM] Share still pending after grace period; rebooting anyway");
      }
      Serial.println("[SYSTEM] Performing scheduled full reboot now");
      delay(100);
      rp2040.reboot();
    }
  }
  if(next_core0_hash_us != 0) {
    int32_t remaining=(int32_t)(next_core0_hash_us-micros());
    if(remaining>1000) {
      if(remaining>100000) remaining=100000;
      delayMicroseconds((uint32_t)remaining);
    }
  } else if(__atomic_load_n(&work_valid,__ATOMIC_ACQUIRE)==0) {
    delay(1);
  }
}

// ============================================================
// CORE 1 - MINING ONLY
// ============================================================

void setup1() {
  delay(1200);
  Serial.println("[CORE1] PI-Flex mining engine online");
}

void loop1() {
  static uint32_t local_generation=0;
  static WorkState local_work;
  static uint64_t nonce1=0;
  static bool have_work=false;
  uint32_t generation=__atomic_load_n(&work_generation,__ATOMIC_ACQUIRE);
  if(!have_work || generation!=local_generation) {
    if(read_work_snapshot(local_work,local_generation)) {
      have_work=true;
      nonce1=((uint64_t)micros()<<21)^0x51F17E57ULL^((uint64_t)local_generation<<9);
    } else {
      delay(1);
      return;
    }
  }

  uint8_t hash[32];
  uint64_t nonce=nonce1++;
  if(!pi_flex_hash_raw(local_work.index,local_work.previous_hash,nonce,hash,ws1))return;
  __atomic_add_fetch(&hashes_core1,1U,__ATOMIC_RELAXED);

  if(__atomic_load_n(&work_generation,__ATOMIC_ACQUIRE)!=local_generation)return;
  if(!meets_rule(hash,local_work.share_rule))return;

  publish_share(nonce,local_work,local_generation,hash);
}
