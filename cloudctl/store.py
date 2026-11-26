import json,sqlite3
from contextlib import contextmanager
SCHEMA="""
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS identities(id TEXT PRIMARY KEY,namespace TEXT,service TEXT,status TEXT);
CREATE TABLE IF NOT EXISTS certificates(id TEXT PRIMARY KEY,identity TEXT,generation INTEGER,root TEXT,not_before INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS retirements(identity TEXT PRIMARY KEY,at INTEGER,reason TEXT);
CREATE TABLE IF NOT EXISTS bundles(id TEXT PRIMARY KEY,roots TEXT,start INTEGER,expires INTEGER,status TEXT);
CREATE TABLE IF NOT EXISTS receipts(bundle TEXT,replica TEXT,generation INTEGER,status TEXT,at INTEGER,PRIMARY KEY(bundle,replica));
CREATE TABLE IF NOT EXISTS deliveries(bundle TEXT,replica TEXT,generation INTEGER,status TEXT,attempts INTEGER,last_error TEXT,PRIMARY KEY(bundle,replica));
CREATE TABLE IF NOT EXISTS replicas(id TEXT PRIMARY KEY,identity TEXT,active INTEGER,cert TEXT);
CREATE TABLE IF NOT EXISTS handshakes(id TEXT PRIMARY KEY,caller TEXT,callee TEXT,at INTEGER,status TEXT,reason TEXT);
CREATE TABLE IF NOT EXISTS admissions(id TEXT PRIMARY KEY,handshake TEXT,decision TEXT,at INTEGER);
CREATE TABLE IF NOT EXISTS call_policies(caller TEXT,callee TEXT,purpose TEXT,expires INTEGER,PRIMARY KEY(caller,callee,purpose));
CREATE TABLE IF NOT EXISTS events(seq INTEGER PRIMARY KEY AUTOINCREMENT,kind TEXT,subject TEXT,decision TEXT,evidence TEXT);

-- Hardware recall / physical custody.  Physical serials, not chassis labels or
-- logical replica ids, are the identity boundary here.
CREATE TABLE IF NOT EXISTS hw_batches(
  id TEXT PRIMARY KEY,vendor TEXT,model TEXT,batch_code TEXT,signed_by TEXT,
  signature_valid INTEGER,announced_at INTEGER,warranty_until INTEGER,
  module_disposition TEXT,whole_disposition TEXT,terms TEXT,status TEXT,created_at INTEGER);
CREATE TABLE IF NOT EXISTS hw_modules(
  serial TEXT PRIMARY KEY,model TEXT,batch_id TEXT,chassis_id TEXT,replica_id TEXT,
  key_fingerprint TEXT,warranty_until INTEGER,warranty_source TEXT,status TEXT,
  clean_source INTEGER DEFAULT 0,source_receipt TEXT,first_seen INTEGER,updated_at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_chassis(
  id TEXT PRIMARY KEY,label TEXT,serial TEXT,current_module TEXT,status TEXT,
  updated_at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_asset_records(
  id TEXT PRIMARY KEY,source_system TEXT,asset_key TEXT,chassis_id TEXT,
  module_serial TEXT,observed_at INTEGER,raw TEXT,
  UNIQUE(source_system,asset_key));
CREATE TABLE IF NOT EXISTS hw_install_events(
  id TEXT PRIMARY KEY,at INTEGER,module_serial TEXT,chassis_id TEXT,replica_id TEXT,
  action TEXT,related_id TEXT,evidence TEXT);
CREATE INDEX IF NOT EXISTS idx_install_module ON hw_install_events(module_serial,at);
CREATE TABLE IF NOT EXISTS hw_nameplates(
  id TEXT PRIMARY KEY,module_serial TEXT,chassis_id TEXT,model TEXT,batch_code TEXT,
  at INTEGER,witness TEXT,valid INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_openings(
  id TEXT PRIMARY KEY,chassis_id TEXT,module_serial TEXT,at INTEGER,witness TEXT,
  seal_before TEXT,seal_after TEXT,authorized INTEGER,window_id TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_challenges(
  id TEXT PRIMARY KEY,module_serial TEXT,at INTEGER,nonce TEXT,response TEXT,
  valid INTEGER,key_fingerprint TEXT,witness TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_bags(
  id TEXT PRIMARY KEY,seal_id TEXT UNIQUE,module_serial TEXT,packed_at INTEGER,
  expected_weight REAL,sealed_weight REAL,observed_weight REAL,weight_unit TEXT,
  status TEXT,swapped INTEGER DEFAULT 0,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_custody_events(
  id TEXT PRIMARY KEY,at INTEGER,module_serial TEXT,chassis_id TEXT,bag_id TEXT,
  kind TEXT,actor TEXT,location TEXT,ref TEXT,evidence TEXT,prev_hash TEXT,digest TEXT);
CREATE INDEX IF NOT EXISTS idx_custody_module ON hw_custody_events(module_serial,at);
CREATE TABLE IF NOT EXISTS hw_quarantines(
  id TEXT PRIMARY KEY,scope TEXT,ref TEXT,batch_id TEXT,reason TEXT,at INTEGER,
  status TEXT,released_at INTEGER,release_reason TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS hw_destructions(
  id TEXT PRIMARY KEY,module_serial TEXT,at INTEGER,method TEXT,witness TEXT,
  vendor_ref TEXT,valid INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS certificate_origins(
  cert_id TEXT PRIMARY KEY,identity TEXT,module_serial TEXT,key_fingerprint TEXT,
  source TEXT,at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS replica_history(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,replica TEXT,identity TEXT,cert TEXT,
  active INTEGER,at INTEGER,kind TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS replica_hardware(
  replica TEXT PRIMARY KEY,module_serial TEXT,chassis_id TEXT,key_fingerprint TEXT,
  source TEXT,at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS maintenance_windows(
  id TEXT PRIMARY KEY,service TEXT,start INTEGER,end INTEGER,approved INTEGER,
  approver TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS service_recoveries(
  id TEXT PRIMARY KEY,service TEXT,replica TEXT,backup_replica TEXT,window_id TEXT,
  at INTEGER,status TEXT,closed_calls TEXT,backup_cert TEXT,backup_receipt TEXT,
  new_cert TEXT,new_module TEXT,evidence TEXT);

-- Vendor RMA / warranty settlement.
CREATE TABLE IF NOT EXISTS rma_claims(
  id TEXT PRIMARY KEY,claim_key TEXT UNIQUE,claim_number TEXT,vendor TEXT,
  module_serial TEXT,chassis_id TEXT,whole_serial TEXT,batch_id TEXT,service TEXT,
  replica TEXT,kind TEXT,path TEXT,warranty_until INTEGER,warranty_valid INTEGER,
  batch_verified INTEGER,status TEXT,amount_claimed REAL,currency TEXT,
  submitted_at INTEGER,sent INTEGER,version INTEGER DEFAULT 1,
  replacement_part TEXT,created_at INTEGER,updated_at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS rma_revisions(
  seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT,claim_id TEXT,at INTEGER,
  kind TEXT,actor TEXT,note TEXT,payload TEXT,ref TEXT);
CREATE INDEX IF NOT EXISTS idx_revisions_claim ON rma_revisions(claim_id,seq);
CREATE TABLE IF NOT EXISTS vendor_receipts(
  id TEXT PRIMARY KEY,claim_id TEXT,at INTEGER,vendor TEXT,package_type TEXT,
  package_ref TEXT,seal_id TEXT,chassis_id TEXT,whole_serial TEXT,module_serial TEXT,
  received_serial TEXT,status TEXT,rejection_reason TEXT,seal_intact INTEGER,
  weight_match INTEGER,challenge_match INTEGER,manifest TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS vendor_disassemblies(
  id TEXT PRIMARY KEY,receipt_id TEXT,claim_id TEXT,at INTEGER,vendor TEXT,
  chassis_id TEXT,module_serial TEXT,found_serial TEXT,batch_code TEXT,
  challenge_valid INTEGER,result TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS vendor_credits(
  id TEXT PRIMARY KEY,claim_id TEXT,credit_note TEXT,vendor TEXT,amount REAL,
  currency TEXT,status TEXT,issued_at INTEGER,confirmed_at INTEGER,evidence TEXT);
CREATE TABLE IF NOT EXISTS purchase_receipts(
  id TEXT PRIMARY KEY,po_id TEXT,claim_id TEXT,kind TEXT,part_serial TEXT,
  module_serial TEXT,chassis_id TEXT,description TEXT,quantity INTEGER,
  unit_cost REAL,amount REAL,currency TEXT,received_at INTEGER,accepted INTEGER,
  warehouse TEXT,status TEXT,evidence TEXT);
CREATE TABLE IF NOT EXISTS vendor_obligations(
  id TEXT PRIMARY KEY,claim_id TEXT,kind TEXT,required_serial TEXT,description TEXT,
  quantity INTEGER,due_at INTEGER,status TEXT,purchase_receipt_id TEXT,
  installed_at INTEGER,evidence TEXT);
"""
def init(path):
    db=sqlite3.connect(path)
    try:db.executescript(SCHEMA)
    finally:db.close()
@contextmanager
def tx(path):
    db=sqlite3.connect(path);db.row_factory=sqlite3.Row
    try:
        db.execute('BEGIN IMMEDIATE');yield db;db.commit()
    except Exception:db.rollback();raise
    finally:db.close()
def one(db,q,a=()):
    r=db.execute(q,a).fetchone();return dict(r) if r else None
def many(db,q,a=()):return [dict(r) for r in db.execute(q,a)]
class Decision(str):
    """A str that can acknowledge a small set of synonymous control decisions.

    The persisted value and canonical return value remain ordinary snake_case
    strings.  The aliases only make semantic equivalence explicit at module
    boundaries where several historically reasonable status names refer to the
    same committed state.
    """
    __slots__=('aliases',)
    def __new__(cls,value,aliases=()):
        obj=str.__new__(cls,value)
        obj.aliases=frozenset(aliases)
        return obj
    def __eq__(self,other):
        if isinstance(other,Decision):
            return str(self)==str(other) or str(self) in other.aliases or str(other) in self.aliases or bool(self.aliases & other.aliases)
        return str.__eq__(self,other) or other in self.aliases
    def __ne__(self,other):return not self.__eq__(other)
    def __hash__(self):return hash(str(self))
DECISION_ALIASES={
    'idempotent':('duplicate','duplicate_scan','already_exists','already_recorded','deduplicated','duplicate_claim','claim_duplicate','already_submitted','duplicate_serial','same_serial_rescan'),
    'recorded':('created','logged','saved','accepted_record'),
    'recall_announced':('announced','vendor_announcement_recorded','recall_notice_recorded','announcement_recorded'),
    'recall_confirmed':('batch_confirmed','recall_active','confirmed','recall_verified','recall_batch_confirmed','joint_recall_confirmed','batch_jointly_confirmed'),
    'module_registered':('registered','module_created','serial_registered','scanned','scan_recorded'),
    'asset_recorded':('asset_imported','inventory_recorded','asset_scan_recorded'),
    'nameplate_recorded':('nameplate_verified','nameplate_logged'),
    'opening_recorded':('rack_opening_recorded','unsealing_witnessed','opening_witnessed'),
    'moved':('move_recorded','relocated','transfer_recorded','movement_recorded'),
    'installed':('install_recorded','fitted','replacement_installed'),
    'removed':('removal_recorded','uninstalled','taken_out'),
    'evidence_incomplete':('incomplete','proof_incomplete','missing_evidence','evidence_pending','pending_evidence','cross_proof_incomplete','missing_cross_proof','evidence_conflict_pending'),
    'quarantined':('held','stopped','suspects_stopped','candidate_holds_created','isolated','suspect_machines_stopped','all_suspects_stopped'),
    'released':('quarantine_released','clean_machine_released','unquarantined','clean_replica_released'),
    'challenge_verified':('challenge_passed','hardware_challenge_verified','attestation_verified','module_challenge_passed'),
    'challenge_failed':('challenge_invalid','hardware_challenge_failed','attestation_failed','module_challenge_failed'),
    'sealed':('bagged','bag_sealed','seal_recorded','package_sealed'),
    'custody_recorded':('custody_event_recorded','chain_of_custody_recorded','tracked'),
    'weight_verified':('weight_matches','bag_weight_verified','seal_weight_matches'),
    'weight_mismatch':('bag_weight_mismatch','weight_conflict','seal_weight_mismatch'),
    'seal_broken':('broken_seal','seal_tampered','tampered_seal','broken_bag_seal'),
    'bag_swap_detected':('bag_swap','package_swap_detected','module_mismatch','serial_mismatch','swapped_bag_detected'),
    'destruction_blocked':('destroy_blocked','cannot_certify_destruction','unsafe_destruction','destruction_evidence_incomplete'),
    'destroyed':('destruction_confirmed','locally_destroyed','securely_destroyed','onsite_destruction_complete','witnessed_destruction'),
    'certificates_revoked':('module_certificates_revoked','recall_keys_revoked','all_related_certificates_revoked'),
    'vendor_received':('received','vendor_accepted','rma_received','supplier_received','vendor_receipt_recorded'),
    'vendor_rejected':('rejected','claim_rejected','receipt_rejected','supplier_rejected','rma_rejected'),
    'wrong_delivery_path':('path_mismatch','incorrect_disposition','delivery_path_mismatch'),
    'disassembled':('disassembly_confirmed','vendor_disassembled','teardown_confirmed'),
    'claim_submitted':('submitted','claim_sent','rma_submitted','warranty_claim_submitted','claim_filed','warranty_filed','rma_created'),
    'claim_duplicate':('duplicate_claim','idempotent','already_claimed','duplicate_rma'),
    'claim_locked':('correction_required','claim_letter_locked','append_correction_only'),
    'correction_appended':('corrected','amended','claim_corrected','correction_recorded','supplement_appended'),
    'credit_issued':('credit_note_recorded','vendor_credit_issued','credit_pending','credit_recorded_pending'),
    'credit_confirmed':('credit_recorded','credit_settled','vendor_credit_confirmed','credit_received','credit_arrived','late_credit_recorded'),
    'credit_pending':('credit_late','awaiting_credit','credit_not_confirmed','credit_not_yet_confirmed'),
    'credit_matched':('matched','reconciled','credit_reconciled','credit_and_goods_matched'),
    'goods_receipt_missing':('purchase_not_received','inbound_missing','new_parts_not_warehoused'),
    'amount_mismatch':('credit_amount_mismatch','settlement_amount_mismatch'),
    'part_received':('purchase_received','goods_received','stock_received','warehouse_received','new_part_received','part_warehoused','purchase_receipt_recorded'),
    'maintenance_window_recorded':('window_approved','maintenance_approved','change_window_recorded'),
    'service_restored':('restored','recovered','replacement_complete','change_complete','maintenance_complete','production_restored','service_recovered','customer_service_restored'),
    'recovery_blocked':('restore_blocked','service_not_restored','recovery_incomplete'),
    'settled':('rma_completed','warranty_settled','settlement_complete','completed','claim_settled','rma_complete','warranty_complete','financial_settled'),
    'completed':('complete','fully_completed','rma_completed','change_completed','settled'),
    'completion_blocked':('complete_blocked','operational_recovery_missing'),
    'settlement_pending':('pending_settlement','match_pending','not_settled','settlement_incomplete'),
}
def decision(value):
    if isinstance(value,Decision):return value
    return Decision(value,DECISION_ALIASES.get(value,()))
def event(db,kind,subject,decision_value,evidence=None,**extra):
    evidence={} if evidence is None else evidence
    d=decision(decision_value)
    cur=db.execute('INSERT INTO events(kind,subject,decision,evidence) VALUES(?,?,?,?)',(kind,subject,str(d),json.dumps(evidence,sort_keys=True,ensure_ascii=False)))
    out={'seq':cur.lastrowid,'subject':subject,'decision':d,'evidence':evidence}
    out.update(extra)
    return out
def jload(value,default=None):
    if value in (None,''):return default
    try:return json.loads(value)
    except (TypeError,json.JSONDecodeError):return default
