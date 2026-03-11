"""
CutPlan Pro v2 — Diamond Fabrics Limited
LAN Multi-User | Reports | Fabric Stock | Multi-Fabric
"""
import os, json, sqlite3, hashlib, secrets, re, io, csv, socket
from datetime import datetime
from functools import wraps
from flask import (Flask, render_template, request, jsonify,
                   session, redirect, send_file)

BASE = os.path.dirname(os.path.abspath(__file__))
# Render free tier has no persistent disk — use /tmp (resets on restart, fine for planner-only use)
# For persistent storage upgrade to Render paid disk or use Railway
_tmp = os.environ.get('DB_DIR', os.path.join(BASE, 'data'))
DB   = os.path.join(_tmp, 'diamond.db')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'diamond-fabrics-v2-' + secrets.token_hex(12))
app.permanent_session_lifetime = 86400 * 14  # 2 weeks

# ═══════════════════════════════════════════════════════
# DATABASE
# ═══════════════════════════════════════════════════════
def getdb():
    c = sqlite3.connect(DB, timeout=30, check_same_thread=False)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    c.execute("PRAGMA synchronous=NORMAL")
    c.execute("PRAGMA cache_size=20000")
    return c

def initdb():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    c = getdb()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        username   TEXT UNIQUE NOT NULL COLLATE NOCASE,
        password   TEXT NOT NULL,
        full_name  TEXT DEFAULT '',
        role       TEXT DEFAULT 'planner',
        department TEXT DEFAULT '',
        active     INTEGER DEFAULT 1,
        last_login TEXT,
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
        id               INTEGER PRIMARY KEY AUTOINCREMENT,
        order_no         TEXT NOT NULL,
        style_no         TEXT DEFAULT '',
        customer         TEXT DEFAULT '',
        cust_po          TEXT DEFAULT '',
        article_no       TEXT DEFAULT '',
        description      TEXT DEFAULT '',
        fabric_width     REAL DEFAULT 166,
        avg_cons         REAL DEFAULT 1.12,
        pocketing_code   TEXT DEFAULT '',
        order_qty        INTEGER DEFAULT 0,
        excess_pct       REAL DEFAULT 3,
        size_data        TEXT DEFAULT '{}',
        fabrics_data     TEXT DEFAULT '[]',
        shrinkage_data   TEXT DEFAULT '{}',
        markers_data     TEXT DEFAULT '[]',
        plan_result      TEXT DEFAULT '{}',
        status           TEXT DEFAULT 'draft',
        notes            TEXT DEFAULT '',
        season           TEXT DEFAULT '',
        created_by       INTEGER,
        updated_by       INTEGER,
        created_at       TEXT DEFAULT CURRENT_TIMESTAMP,
        updated_at       TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS fabric_stock (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        shrink_type  TEXT UNIQUE NOT NULL,
        available_m  REAL DEFAULT 0,
        reserved_m   REAL DEFAULT 0,
        notes        TEXT DEFAULT '',
        updated_by   INTEGER,
        updated_at   TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS activity_log (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        username   TEXT,
        action     TEXT,
        order_id   INTEGER,
        ip_addr    TEXT DEFAULT '',
        details    TEXT DEFAULT '',
        created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    """)
    # Default users
    for uname, pw, role, fname, dept in [
        ('admin',    'admin123', 'admin',   'Administrator',  'Management'),
        ('planner1', 'plan123',  'planner', 'Planner One',    'Cutting'),
        ('planner2', 'plan456',  'planner', 'Planner Two',    'Cutting'),
        ('manager',  'mgr123',   'manager', 'Floor Manager',  'Production'),
        ('cutter1',  'cut123',   'viewer',  'Cutter One',     'Cutting Floor'),
    ]:
        try:
            c.execute("INSERT INTO users(username,password,full_name,role,department) VALUES(?,?,?,?,?)",
                      (uname, _hash(pw), fname, role, dept))
        except: pass
    # Default stock
    for sh in ['3X2','3X3','2X2','4X3','F/L']:
        try: c.execute("INSERT INTO fabric_stock(shrink_type,available_m) VALUES(?,0)", (sh,))
        except: pass
    c.commit(); c.close()

def _hash(p): return hashlib.sha256(p.encode()).hexdigest()
def _log(uid, uname, action, oid=None, detail=''):
    try:
        c = getdb()
        ip = request.remote_addr if request else ''
        c.execute("INSERT INTO activity_log(user_id,username,action,order_id,ip_addr,details) VALUES(?,?,?,?,?,?)",
                  (uid, uname, action, oid, ip, detail))
        c.commit(); c.close()
    except: pass

# ═══════════════════════════════════════════════════════
# AUTH
# ═══════════════════════════════════════════════════════
def auth(f):
    @wraps(f)
    def d(*a,**k):
        if 'uid' not in session:
            if request.is_json: return jsonify({'error':'Not logged in'}),401
            return redirect('/login')
        return f(*a,**k)
    return d

def admin_only(f):
    @wraps(f)
    def d(*a,**k):
        if session.get('role') not in ('admin',):
            return jsonify({'error':'Admin only'}),403
        return f(*a,**k)
    return d

# ═══════════════════════════════════════════════════════
# PAGES
# ═══════════════════════════════════════════════════════
@app.route('/')
@auth
def index(): return render_template('app.html')

@app.route('/login')
def login_page():
    if 'uid' in session: return redirect('/')
    return render_template('login.html')

@app.route('/logout')
def logout():
    if 'uid' in session: _log(session['uid'], session.get('uname',''), 'logout')
    session.clear()
    return redirect('/login')

# ═══════════════════════════════════════════════════════
# AUTH API
# ═══════════════════════════════════════════════════════
@app.route('/api/login', methods=['POST'])
def do_login():
    d = request.json or {}
    un = (d.get('username') or '').strip()
    pw = d.get('password','')
    c = getdb()
    u = c.execute("SELECT * FROM users WHERE username=? AND password=? AND active=1",
                  (un, _hash(pw))).fetchone()
    if u:
        c.execute("UPDATE users SET last_login=CURRENT_TIMESTAMP WHERE id=?", (u['id'],))
        c.commit()
    c.close()
    if not u: return jsonify({'ok':False,'error':'Invalid username or password'}),401
    session.permanent = True
    session.update({'uid':u['id'],'uname':u['username'],'fname':u['full_name'],'role':u['role']})
    _log(u['id'], u['username'], 'login')
    return jsonify({'ok':True,'username':u['username'],'role':u['role'],'fname':u['full_name']})

@app.route('/api/me')
@auth
def me():
    return jsonify({'uid':session['uid'],'uname':session['uname'],
                    'fname':session.get('fname',''),'role':session['role']})

# ═══════════════════════════════════════════════════════
# PDF PARSER (no external deps)
# ═══════════════════════════════════════════════════════
@app.route('/api/parse-pdf', methods=['POST'])
@auth
def parse_pdf():
    if 'file' not in request.files: return jsonify({'error':'No file'}),400
    f = request.files['file']
    if not f.filename.lower().endswith('.pdf'): return jsonify({'error':'PDF only'}),400
    raw = f.read()
    text = _pdf_text(raw)
    return jsonify(_parse(text))

def _pdf_text(raw):
    try: t = raw.decode('latin-1', errors='ignore')
    except: t = ''
    parts = re.findall(r'\(([^\)]{1,300})\)', t)
    for blk in re.findall(r'BT(.*?)ET', t, re.DOTALL):
        parts += re.findall(r'\(([^\)]{1,300})\)\s*T[jJ]', blk)
    text = ' '.join(parts)
    text = re.sub(r'[^\x20-\x7E\n]', ' ', text)
    return re.sub(r' {3,}', '  ', text)

def _parse(text):
    r = {}
    def g(pats, cast=str):
        for p in pats:
            m = re.search(p, text, re.I)
            if m:
                try: return cast(m.group(1).strip().rstrip('.,:'))
                except: pass
        return None
    r['order_no']    = g([r'Sale\s*Order\s*No[:\s#]+(\d{5,12})', r'Order\s*No[:\s#]+(\d{5,12})'])
    r['style_no']    = g([r'Style\s*No[:\s]+([A-Z0-9\-]{3,14})', r'Style[:\s]+([A-Z0-9\-]{3,14})'])
    r['customer']    = g([r'Customer[:\s]+([A-Z][A-Z\s\.&,]+?)(?=\s{2}|\n|Order|Cust)',
                          r'Buyer[:\s]+([A-Z][A-Z\s\.&,]+?)(?=\s{2}|\n)'])
    r['cust_po']     = g([r'Cust\.?\s*PO\s*(?:No)?[:\s]+(\d{5,14})'])
    r['article_no']  = g([r'Article\s*(?:No)?[:\s]+([A-Z0-9\-]+)'])
    r['order_qty']   = g([r'Order\s*Qty[:\s]+(\d{3,7})', r'Total\s*Qty[:\s]+(\d{3,7})'], int)
    r['excess_pct']  = g([r'Extra\s*Cut\s*%[:\s]+(\d+\.?\d*)', r'Excess[:\s]+(\d+\.?\d*)\s*%'], float)
    r['avg_cons']    = g([r'Avg\.?\s*Cons[:\s]*[\w\s]*?(\d+\.\d{2,3})',
                          r'Consumption[:\s]*[\w\s]*?(\d+\.\d{2,3})'], float)
    r['fabric_width']= g([r'Width[:\s]*(\d{2,3})\s*[cC][mM]'], float)
    r['description'] = g([r'Description[:\s]+([A-Z][A-Z0-9 \/\-]{5,80}(?:JEANS?|TROUSER|PANT|SHIRT|TOP|JACKET|DRESS)[A-Z0-9 \-]{0,40})'])
    # Fabric code detection (first one found)
    m = re.search(r'((?:SA|FA|FB|SB|SC)-[\d\w\/\-P]+)', text)
    if m: r['fabric_code'] = m.group(1)
    # Size detection
    nums = [int(x) for x in re.findall(r'\b(\d{2,4})\b', text)]
    sd = _detect_sizes(nums, [32,34,36,38,40,42,44,46], r.get('order_qty'))
    if sd: r['size_data'] = sd
    return {k:v for k,v in r.items() if v is not None}

def _detect_sizes(nums, sizes, known_total=None):
    for i in range(len(nums)-7):
        chunk = nums[i:i+8]
        total = sum(chunk)
        if all(5 <= v <= 2000 for v in chunk) and 100 <= total <= 20000:
            if known_total and abs(total-known_total) > known_total*0.08: continue
            return {str(s): chunk[j] for j,s in enumerate(sizes)}
    return None

# ═══════════════════════════════════════════════════════
# SMART OPTIMIZER
# ═══════════════════════════════════════════════════════
SIZES   = [32,34,36,38,40,42,44,46]
SHRINKS = ['3X2','3X3','2X2','4X3','F/L']

@app.route('/api/optimize', methods=['POST'])
@auth
def optimize():
    d      = request.json or {}
    sz_qty = {int(k):int(v) for k,v in d.get('size_qty',{}).items() if int(v)>0}
    shrink = {k:float(v) for k,v in d.get('shrinkage',{}).items() if float(v)>0}
    avg    = float(d.get('avg_cons',1.12))
    ex_pct = float(d.get('excess_pct',3))/100
    max_b  = min(int(d.get('max_bundles',10)),10)

    req = {s: int(sz_qty.get(s,0)*(1+ex_pct)+0.9999) if sz_qty.get(s,0) else 0 for s in SIZES}
    total_req = sum(req.values())
    remaining = {s:req[s] for s in SIZES}
    fab_avail = dict(shrink)
    markers = []

    # Phase 1 — shrinkage fabrics
    for fab in ['3X2','3X3','2X2','4X3']:
        avail = fab_avail.get(fab,0)
        if avail < avg: continue
        n_sz = int(fab.split('X')[0])
        itr = 0
        while avail >= avg*2 and itr < 80:
            itr += 1
            active = [(s,remaining[s]) for s in SIZES if remaining[s]>0]
            if not active: break
            active.sort(key=lambda x:-x[1])
            grp = [s for s,_ in active[:min(n_sz,max_b)]]
            if not grp: break
            mkr_len = avg*len(grp)
            if mkr_len > avail:
                grp = grp[:max(1,int(avail/avg))]
                mkr_len = avg*len(grp)
            if mkr_len > avail: break
            max_p = int(avail/mkr_len)
            if max_p < 1: break
            needs = {s:remaining[s] for s in grp}
            max_n = max(needs.values())
            sz_r = {}
            for s in grp:
                if needs[s]<=0: continue
                sz_r[s] = 2 if needs[s]>=max_n*1.6 and len(grp)<max_b else 1
            if not sz_r: break
            ppp = sum(sz_r.values())
            p_need = max(int(remaining[s]/sz_r[s]) for s in sz_r)
            plies = min(max_p, p_need)
            if plies < 1: break
            used = round(plies*mkr_len,2)
            markers.append({'shrink':fab,'shade':'','sizes':sz_r,'plies':plies,
                            'ppp':ppp,'cutQty':plies*ppp,'mLen':round(mkr_len,2),'metersUsed':used})
            avail -= used; fab_avail[fab]=round(avail,2)
            for s,rt in sz_r.items(): remaining[s]=max(0,remaining[s]-plies*rt)

    # Phase 2 — F/L balance
    fl = fab_avail.get('F/L',0)
    bal = [(s,remaining[s]) for s in SIZES if remaining[s]>0]
    bal.sort(key=lambda x:-x[1])
    itr = 0
    while fl>=avg and bal and itr<50:
        itr+=1
        grp=[s for s,_ in bal[:min(4,max_b)]]
        mkr_len=avg*len(grp)
        if mkr_len>fl:
            grp=grp[:max(1,int(fl/avg))]; mkr_len=avg*len(grp)
        if mkr_len>fl or not grp: break
        max_p=int(fl/mkr_len)
        sz_r={s:1 for s in grp if remaining[s]>0}
        if not sz_r: break
        ppp=sum(sz_r.values())
        p_need=max(int(remaining[s]/sz_r[s]) for s in sz_r)
        plies=min(max_p,p_need)
        if plies<1: break
        used=round(plies*mkr_len,2)
        markers.append({'shrink':'F/L','shade':'F/L','sizes':sz_r,'plies':plies,
                        'ppp':ppp,'cutQty':plies*ppp,'mLen':round(mkr_len,2),'metersUsed':used})
        fl-=used; fab_avail['F/L']=round(fl,2)
        for s,rt in sz_r.items(): remaining[s]=max(0,remaining[s]-plies*rt)
        bal=[(s,remaining[s]) for s in SIZES if remaining[s]>0]; bal.sort(key=lambda x:-x[1])

    for i,m in enumerate(markers): m['num']=i+1
    sz_plan={s:0 for s in SIZES}; tac=0; tm=0; tp=0
    for m in markers:
        for s,rt in m['sizes'].items(): sz_plan[s]=sz_plan.get(s,0)+m['plies']*rt
        tac+=m['cutQty']; tm+=m['metersUsed']; tp+=m['plies']
    tm=round(tm,1)
    fab_used={};
    for m in markers: fab_used[m['shrink']]=round(fab_used.get(m['shrink'],0)+m['metersUsed'],1)
    fab_rem={t:round(shrink.get(t,0)-fab_used.get(t,0),1) for t in shrink}
    tav=sum(shrink.values())
    return jsonify({'ok':True,'markers':markers,'size_plan':sz_plan,'size_req':req,
        'balance':{s:sz_plan[s]-req[s] for s in SIZES},'total_cut':tac,'total_req':total_req,
        'total_meters':tm,'total_plies':tp,'fab_used':fab_used,'fab_remaining':fab_rem,
        'efficiency':round(tac/total_req*100,1) if total_req else 0,
        'waste_pct':round(tm/tav*100,1) if tav else 0,
        'uncut':{s:v for s,v in remaining.items() if v>0}})

# ═══════════════════════════════════════════════════════
# ORDERS CRUD
# ═══════════════════════════════════════════════════════
@app.route('/api/orders', methods=['GET'])
@auth
def list_orders():
    c=getdb()
    rows=c.execute("""
        SELECT o.id,o.order_no,o.style_no,o.customer,o.cust_po,o.article_no,
               o.order_qty,o.status,o.season,o.updated_at,o.created_at,
               u.username as by_user,u.full_name as by_name
        FROM orders o LEFT JOIN users u ON o.created_by=u.id
        ORDER BY o.updated_at DESC""").fetchall()
    c.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/orders/<int:oid>', methods=['GET'])
@auth
def get_order(oid):
    c=getdb(); row=c.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone(); c.close()
    if not row: return jsonify({'error':'Not found'}),404
    o=dict(row)
    for f in ['size_data','shrinkage_data','markers_data','plan_result']:
        try: o[f]=json.loads(o[f] or '{}')
        except: o[f]={}
    try: o['fabrics_data']=json.loads(o['fabrics_data'] or '[]')
    except: o['fabrics_data']=[]
    return jsonify(o)

def _ord_payload(d):
    return (d.get('order_no',''),d.get('style_no',''),d.get('customer',''),
            d.get('cust_po',''),d.get('article_no',''),d.get('description',''),
            d.get('fabric_width',166),d.get('avg_cons',1.12),d.get('pocketing_code',''),
            d.get('order_qty',0),d.get('excess_pct',3),
            json.dumps(d.get('size_data',{})),
            json.dumps(d.get('fabrics_data',[])),
            json.dumps(d.get('shrinkage_data',{})),
            json.dumps(d.get('markers_data',[])),
            json.dumps(d.get('plan_result',{})),
            d.get('status','draft'),d.get('notes',''),d.get('season',''))

@app.route('/api/orders', methods=['POST'])
@auth
def create_order():
    d=request.json or {}
    c=getdb()
    cur=c.execute("""INSERT INTO orders(order_no,style_no,customer,cust_po,article_no,description,
        fabric_width,avg_cons,pocketing_code,order_qty,excess_pct,size_data,fabrics_data,
        shrinkage_data,markers_data,plan_result,status,notes,season,created_by,updated_by)
        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        _ord_payload(d)+(session['uid'],session['uid']))
    c.commit(); nid=cur.lastrowid; c.close()
    _log(session['uid'],session['uname'],'create_order',nid,d.get('order_no',''))
    return jsonify({'ok':True,'id':nid})

@app.route('/api/orders/<int:oid>', methods=['PUT'])
@auth
def update_order(oid):
    d=request.json or {}
    c=getdb()
    c.execute("""UPDATE orders SET order_no=?,style_no=?,customer=?,cust_po=?,article_no=?,
        description=?,fabric_width=?,avg_cons=?,pocketing_code=?,order_qty=?,excess_pct=?,
        size_data=?,fabrics_data=?,shrinkage_data=?,markers_data=?,plan_result=?,
        status=?,notes=?,season=?,updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE id=?""",
        _ord_payload(d)+(session['uid'],oid))
    c.commit(); c.close()
    _log(session['uid'],session['uname'],'update_order',oid)
    return jsonify({'ok':True})

@app.route('/api/orders/<int:oid>/status', methods=['POST'])
@auth
def set_status(oid):
    st=request.json.get('status','draft')
    c=getdb(); c.execute("UPDATE orders SET status=?,updated_at=CURRENT_TIMESTAMP WHERE id=?",(st,oid))
    c.commit(); c.close()
    _log(session['uid'],session['uname'],'status_'+st,oid)
    return jsonify({'ok':True})

@app.route('/api/orders/<int:oid>', methods=['DELETE'])
@auth
@admin_only
def delete_order(oid):
    c=getdb(); c.execute('DELETE FROM orders WHERE id=?',(oid,)); c.commit(); c.close()
    _log(session['uid'],session['uname'],'delete_order',oid)
    return jsonify({'ok':True})

# CSV export
@app.route('/api/orders/<int:oid>/csv')
@auth
def export_csv(oid):
    c=getdb(); row=c.execute('SELECT * FROM orders WHERE id=?',(oid,)).fetchone(); c.close()
    if not row: return jsonify({'error':'Not found'}),404
    o=dict(row)
    try: plan=json.loads(o.get('plan_result') or '{}')
    except: plan={}
    markers=plan.get('markers',[])
    buf=io.StringIO(); w=csv.writer(buf)
    sz_cols=['Sz'+str(s) for s in SIZES]
    w.writerow(['Lay#','MarkerName','Order','Style','Article','Shrinkage','Shade',
                'Plies','MkrLen_m','TotalMeters_m']+sz_cols+['CutTotal'])
    for i,m in enumerate(markers):
        szv=[m['plies']*(m.get('sizes',{}).get(s,m.get('sizes',{}).get(str(s),0))) for s in SIZES]
        w.writerow([i+1,f"{o['style_no']}_MKR{m['num']}_{m['shrink']}",
                    o['order_no'],o['style_no'],o.get('article_no',''),
                    m['shrink'],m.get('shade','A'),m['plies'],m['mLen'],m['metersUsed']]+szv+[m['cutQty']])
    buf.seek(0)
    _log(session['uid'],session['uname'],'export_csv',oid)
    return send_file(io.BytesIO(buf.read().encode()),mimetype='text/csv',as_attachment=True,
                     download_name=f"CutPlan_{o['order_no']}_{o['style_no']}.csv")

# ═══════════════════════════════════════════════════════
# FABRIC STOCK
# ═══════════════════════════════════════════════════════
@app.route('/api/stock', methods=['GET'])
@auth
def get_stock():
    c=getdb(); rows=c.execute("SELECT * FROM fabric_stock ORDER BY id").fetchall(); c.close()
    return jsonify([dict(r) for r in rows])

@app.route('/api/stock', methods=['POST'])
@auth
def update_stock():
    items=request.json or []
    c=getdb()
    for item in items:
        c.execute("""UPDATE fabric_stock SET available_m=?,reserved_m=?,notes=?,
                     updated_by=?,updated_at=CURRENT_TIMESTAMP WHERE shrink_type=?""",
                  (item.get('available_m',0),item.get('reserved_m',0),
                   item.get('notes',''),session['uid'],item['shrink_type']))
    c.commit(); c.close()
    return jsonify({'ok':True})

# ═══════════════════════════════════════════════════════
# USERS
# ═══════════════════════════════════════════════════════
@app.route('/api/users', methods=['GET'])
@auth
@admin_only
def list_users():
    c=getdb()
    rows=c.execute("SELECT id,username,full_name,department,role,active,last_login,created_at FROM users ORDER BY role,username").fetchall()
    c.close(); return jsonify([dict(r) for r in rows])

@app.route('/api/users', methods=['POST'])
@auth
@admin_only
def create_user():
    d=request.json or {}
    if not d.get('username') or not d.get('password'):
        return jsonify({'error':'Username and password required'}),400
    c=getdb()
    try:
        c.execute("INSERT INTO users(username,password,full_name,department,role) VALUES(?,?,?,?,?)",
                  (d['username'].strip(),_hash(d['password']),d.get('full_name',''),d.get('department',''),d.get('role','planner')))
        c.commit(); c.close(); return jsonify({'ok':True})
    except sqlite3.IntegrityError: return jsonify({'error':'Username already exists'}),400

@app.route('/api/users/<int:uid>/toggle', methods=['POST'])
@auth
@admin_only
def toggle_user(uid):
    if uid==1: return jsonify({'error':'Cannot disable admin'}),400
    c=getdb(); c.execute("UPDATE users SET active=1-active WHERE id=?",(uid,))
    c.commit(); c.close(); return jsonify({'ok':True})

@app.route('/api/users/<int:uid>/password', methods=['POST'])
@auth
@admin_only
def reset_pw(uid):
    pw=(request.json or {}).get('password','')
    if not pw: return jsonify({'error':'Password required'}),400
    c=getdb(); c.execute("UPDATE users SET password=? WHERE id=?",(_hash(pw),uid))
    c.commit(); c.close(); return jsonify({'ok':True})

# ═══════════════════════════════════════════════════════
# STATS + REPORTS
# ═══════════════════════════════════════════════════════
@app.route('/api/stats')
@auth
def stats():
    c=getdb()
    def cnt(q): return c.execute(q).fetchone()[0]
    data={
        'total':  cnt("SELECT COUNT(*) FROM orders"),
        'draft':  cnt("SELECT COUNT(*) FROM orders WHERE status='draft'"),
        'final':  cnt("SELECT COUNT(*) FROM orders WHERE status='final'"),
        'today':  cnt("SELECT COUNT(*) FROM orders WHERE DATE(created_at)=DATE('now')"),
        'users_active': cnt("SELECT COUNT(*) FROM users WHERE active=1"),
        'total_cut_qty': c.execute("SELECT COALESCE(SUM(order_qty),0) FROM orders WHERE status='final'").fetchone()[0],
        'recent': [dict(r) for r in c.execute("""
            SELECT o.id,o.order_no,o.customer,o.style_no,o.order_qty,o.status,o.updated_at,u.username
            FROM orders o LEFT JOIN users u ON o.created_by=u.id ORDER BY o.updated_at DESC LIMIT 10""").fetchall()],
        'activity': [dict(r) for r in c.execute("""
            SELECT username,action,details,order_id,created_at
            FROM activity_log ORDER BY created_at DESC LIMIT 12""").fetchall()]
    }
    c.close(); return jsonify(data)

@app.route('/api/reports/monthly')
@auth
def monthly_report():
    c=getdb()
    monthly=c.execute("""
        SELECT strftime('%Y-%m', created_at) as month,
               COUNT(*) as orders,
               SUM(order_qty) as total_qty,
               SUM(CASE WHEN status='final' THEN order_qty ELSE 0 END) as finalized_qty,
               COUNT(DISTINCT customer) as customers
        FROM orders GROUP BY month ORDER BY month DESC LIMIT 12
    """).fetchall()
    by_customer=c.execute("""
        SELECT customer, COUNT(*) as orders, SUM(order_qty) as total_qty
        FROM orders WHERE customer!='' GROUP BY customer ORDER BY total_qty DESC LIMIT 10
    """).fetchall()
    by_status=c.execute("""
        SELECT status, COUNT(*) as cnt, SUM(order_qty) as qty
        FROM orders GROUP BY status
    """).fetchall()
    top_styles=c.execute("""
        SELECT style_no, COUNT(*) as orders, SUM(order_qty) as qty
        FROM orders WHERE style_no!='' GROUP BY style_no ORDER BY qty DESC LIMIT 8
    """).fetchall()
    c.close()
    return jsonify({
        'monthly':      [dict(r) for r in monthly],
        'by_customer':  [dict(r) for r in by_customer],
        'by_status':    [dict(r) for r in by_status],
        'top_styles':   [dict(r) for r in top_styles],
    })

# ═══════════════════════════════════════════════════════
# STARTUP — runs under both `python app.py` AND gunicorn
# ═══════════════════════════════════════════════════════
initdb()   # safe to call multiple times; uses CREATE IF NOT EXISTS

if __name__=='__main__':
    try:
        s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.connect(("8.8.8.8",80))
        lan=s.getsockname()[0]; s.close()
    except: lan="127.0.0.1"
    print("\n"+"═"*56)
    print("  ✂️  CutPlan Pro v2 — Diamond Fabrics Limited")
    print("═"*56)
    print(f"  🖥️   Local:   http://127.0.0.1:5000")
    print(f"  🏭   Network: http://{lan}:5000")
    print()
    print("  Users:  admin/admin123  |  planner1/plan123")
    print("          manager/mgr123  |  cutter1/cut123")
    print("═"*56+"\n")
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
