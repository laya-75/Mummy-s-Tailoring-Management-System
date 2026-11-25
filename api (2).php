<?php
declare(strict_types=1);
require_once __DIR__ . '/config.php';
session_start();
header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

function reply(array $data, int $code=200): never {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}
function input_data(): array {
    $v = json_decode(file_get_contents('php://input'), true);
    return is_array($v) ? $v : [];
}
function require_login(): void {
    if (empty($_SESSION['user_id'])) reply(['error'=>'Login required'], 401);
}
function require_admin(): void {
    require_login();
    if (($_SESSION['user_role'] ?? '') !== 'admin') reply(['error'=>'Admin permission required'], 403);
}
function is_post(): bool { return ($_SERVER['REQUEST_METHOD'] ?? '') === 'POST'; }

try {
    $pdo = db();
    $action = $_GET['action'] ?? '';

    if ($action === 'login' && is_post()) {
        $b = input_data();
        $st = $pdo->prepare('SELECT id,name,email,password,role FROM users WHERE email=? LIMIT 1');
        $st->execute([trim((string)($b['email'] ?? ''))]);
        $u = $st->fetch(PDO::FETCH_ASSOC);
        if (!$u || !password_verify((string)($b['password'] ?? ''), (string)$u['password'])) {
            reply(['error'=>'Email ya password galat hai'], 401);
        }
        $role = strtolower((string)($u['role'] ?? ''));
        if (!in_array($role, ['admin','viewer'], true)) $role = 'viewer';
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int)$u['id'];
        $_SESSION['user_name'] = (string)$u['name'];
        $_SESSION['user_role'] = $role;
        reply(['ok'=>true, 'name'=>$u['name'], 'email'=>$u['email'], 'role'=>$role]);
    }

    if ($action === 'logout' && is_post()) {
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time()-42000, $params['path'], $params['domain'], $params['secure'], $params['httponly']);
        }
        session_destroy();
        reply(['ok'=>true]);
    }

    if ($action === 'me') {
        reply(['logged_in'=>!empty($_SESSION['user_id']), 'name'=>$_SESSION['user_name'] ?? null, 'role'=>$_SESSION['user_role'] ?? null]);
    }

    require_login();

    if ($action === 'all') {
        $customers = $pdo->query('SELECT id,name,phone,address AS notes FROM customers ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($customers as &$c) $c['id'] = (string)$c['id'];
        unset($c);
        $orders = $pdo->query('SELECT id,customer_id AS customerId,DATE_FORMAT(order_date,"%Y-%m-%d") AS date,DATE_FORMAT(delivery_date,"%Y-%m-%d") AS delivery,status,total_amount AS total,notes FROM orders ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($orders as &$o) {
            $o['id'] = (string)$o['id']; $o['customerId'] = (string)$o['customerId']; $o['total'] = (float)$o['total'];
            $st = $pdo->prepare('SELECT service_name AS name,quantity AS qty,rate,amount AS total FROM order_services WHERE order_id=? ORDER BY id');
            $st->execute([(int)$o['id']]); $o['items'] = $st->fetchAll(PDO::FETCH_ASSOC);
            foreach ($o['items'] as &$it) { $it['qty']=(int)$it['qty']; $it['rate']=(float)$it['rate']; $it['total']=(float)$it['total']; }
            unset($it); $o['work'] = implode(', ', array_column($o['items'], 'name'));
        }
        unset($o);
        $payments = $pdo->query('SELECT id,order_id AS orderId,amount,DATE_FORMAT(payment_date,"%Y-%m-%d") AS date,payment_method AS note FROM payments ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($payments as &$p) { $p['id']=(string)$p['id']; $p['orderId']=(string)$p['orderId']; $p['amount']=(float)$p['amount']; }
        unset($p);
        reply(['customers'=>$customers, 'orders'=>$orders, 'payments'=>$payments]);
    }

    if ($action === 'create_viewer' && is_post()) {
        require_admin();
        $b = input_data();
        $name = trim((string)($b['name'] ?? ''));
        $email = strtolower(trim((string)($b['email'] ?? '')));
        $password = (string)($b['password'] ?? '');
        if ($name === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($password) < 8) {
            reply(['error'=>'Naam, valid email aur kam se kam 8-character password zaroori hai'], 400);
        }
        $st = $pdo->prepare('SELECT id FROM users WHERE email=? LIMIT 1'); $st->execute([$email]);
        if ($st->fetch()) reply(['error'=>'Is email se account pehle se hai'], 409);
        $st = $pdo->prepare('INSERT INTO users(name,email,password,role) VALUES(?,?,?,?)');
        $st->execute([$name,$email,password_hash($password, PASSWORD_DEFAULT),'viewer']);
        reply(['ok'=>true,'id'=>(string)$pdo->lastInsertId()]);
    }

    // Every data-changing action is admin-only. Viewers can only use action=all.
    if (in_array($action, ['save_customer','save_order','save_payment','update_customer','update_order','update_payment','update_status','delete_order','delete_customer'], true)) require_admin();

    if ($action === 'save_customer' && is_post()) {
        $b=input_data(); $name=trim((string)($b['name']??''));
        if ($name==='') reply(['error'=>'Customer name required'],400);
        $st=$pdo->prepare('INSERT INTO customers(name,phone,address) VALUES(?,?,?)');
        $st->execute([$name,trim((string)($b['phone']??'')),trim((string)($b['notes']??''))]);
        reply(['ok'=>true,'id'=>(string)$pdo->lastInsertId()]);
    }

    if ($action === 'save_order' && is_post()) {
        $b=input_data(); $customerId=(int)($b['customerId']??0); $date=(string)($b['date']??''); $items=$b['items']??[];
        if ($customerId<1 || !preg_match('/^\d{4}-\d{2}-\d{2}$/',$date) || !is_array($items) || !$items) reply(['error'=>'Customer, date aur kam se kam ek service zaroori hai'],400);
        $check=$pdo->prepare('SELECT id FROM customers WHERE id=?'); $check->execute([$customerId]); if(!$check->fetch()) reply(['error'=>'Customer nahi mila'],404);
        $total=0;
        foreach($items as $it){$q=(int)($it['qty']??0);$r=(float)($it['rate']??-1);if($q<1||$r<0)reply(['error'=>'Quantity ya rate galat hai'],400);$total+=$q*$r;}
        $status=(string)($b['status']??'Received');$allowed=['Received','Work in Progress','Completed','Delivered'];if(!in_array($status,$allowed,true))$status='Received';
        $st=$pdo->prepare('INSERT INTO orders(customer_id,order_date,delivery_date,status,total_amount,notes) VALUES(?,?,?,?,?,?)');
        $delivery=trim((string)($b['delivery']??''));$st->execute([$customerId,$date,$delivery!==''?$delivery:null,$status,$total,(string)($b['notes']??'')]);$orderId=(int)$pdo->lastInsertId();
        $ss=$pdo->prepare('INSERT INTO order_services(order_id,service_name,quantity,rate,amount) VALUES(?,?,?,?,?)');
        foreach($items as $it){$q=(int)$it['qty'];$r=(float)$it['rate'];$ss->execute([$orderId,(string)$it['name'],$q,$r,$q*$r]);}
        $advance=(float)($b['advance']??0);if($advance>0){$pp=$pdo->prepare('INSERT INTO payments(order_id,amount,payment_date,payment_method) VALUES(?,?,?,?)');$pp->execute([$orderId,$advance,$date,'Advance']);}
        reply(['ok'=>true,'id'=>(string)$orderId,'total'=>$total]);
    }

    if ($action === 'save_payment' && is_post()) {
        $b=input_data();$orderId=(int)($b['orderId']??0);$amount=(float)($b['amount']??0);$date=(string)($b['date']??'');
        if($orderId<1||$amount<=0||!preg_match('/^\d{4}-\d{2}-\d{2}$/',$date))reply(['error'=>'Payment details galat hain'],400);
        $st=$pdo->prepare('INSERT INTO payments(order_id,amount,payment_date,payment_method) VALUES(?,?,?,?)');$st->execute([$orderId,$amount,$date,(string)($b['note']??'')]);
        reply(['ok'=>true,'id'=>(string)$pdo->lastInsertId()]);
    }
    if ($action === 'update_customer' && is_post()) {
        $b=input_data(); $id=(int)($b['id']??0); $name=trim((string)($b['name']??''));
        if($id<1 || $name==='') reply(['error'=>'Customer ID aur naam zaroori hain'],400);
        $st=$pdo->prepare('UPDATE customers SET name=?,phone=?,address=? WHERE id=?');
        $st->execute([$name,trim((string)($b['phone']??'')),trim((string)($b['notes']??'')),$id]);
        if(!$st->rowCount() && !$pdo->query('SELECT id FROM customers WHERE id='.(int)$id)->fetch()) reply(['error'=>'Customer nahi mila'],404);
        reply(['ok'=>true]);
    }
    if ($action === 'update_order' && is_post()) {
        $b=input_data(); $id=(int)($b['id']??0); $customerId=(int)($b['customerId']??0);
        $date=(string)($b['date']??''); $items=$b['items']??[];
        if($id<1 || $customerId<1 || !preg_match('/^\\d{4}-\\d{2}-\\d{2}$/',$date) || !is_array($items) || !$items) reply(['error'=>'Order details galat hain'],400);
        $check=$pdo->prepare('SELECT id FROM customers WHERE id=?'); $check->execute([$customerId]); if(!$check->fetch()) reply(['error'=>'Customer nahi mila'],404);
        $allowed=['Received','Work in Progress','Completed','Delivered']; $status=(string)($b['status']??'Received'); if(!in_array($status,$allowed,true)) reply(['error'=>'Invalid status'],400);
        $total=0; foreach($items as $it){$q=(int)($it['qty']??0);$r=(float)($it['rate']??-1);$name=trim((string)($it['name']??''));if($q<1||$r<0||$name==='')reply(['error'=>'Service, quantity ya rate galat hai'],400);$total+=$q*$r;}
        $pdo->beginTransaction();
        try {
            $st=$pdo->prepare('UPDATE orders SET customer_id=?,order_date=?,delivery_date=?,status=?,total_amount=?,notes=? WHERE id=?');
            $delivery=trim((string)($b['delivery']??'')); $st->execute([$customerId,$date,$delivery!==''?$delivery:null,$status,$total,(string)($b['notes']??''),$id]);
            if(!$st->rowCount() && !$pdo->query('SELECT id FROM orders WHERE id='.(int)$id)->fetch()) throw new RuntimeException('Order nahi mila');
            $pdo->prepare('DELETE FROM order_services WHERE order_id=?')->execute([$id]);
            $ss=$pdo->prepare('INSERT INTO order_services(order_id,service_name,quantity,rate,amount) VALUES(?,?,?,?,?)');
            foreach($items as $it){$q=(int)$it['qty'];$r=(float)$it['rate'];$ss->execute([$id,trim((string)$it['name']),$q,$r,$q*$r]);}
            $pdo->commit();
        } catch(Throwable $e) { if($pdo->inTransaction())$pdo->rollBack(); throw $e; }
        reply(['ok'=>true,'total'=>$total]);
    }
    if ($action === 'update_payment' && is_post()) {
        $b=input_data(); $id=(int)($b['id']??0); $amount=(float)($b['amount']??0); $date=(string)($b['date']??'');
        if($id<1||$amount<=0||!preg_match('/^\\d{4}-\\d{2}-\\d{2}$/',$date)) reply(['error'=>'Payment details galat hain'],400);
        $st=$pdo->prepare('UPDATE payments SET amount=?,payment_date=?,payment_method=? WHERE id=?');
        $st->execute([$amount,$date,(string)($b['note']??''),$id]);
        if(!$st->rowCount() && !$pdo->query('SELECT id FROM payments WHERE id='.(int)$id)->fetch()) reply(['error'=>'Payment nahi mila'],404);
        reply(['ok'=>true]);
    }
    if ($action === 'update_status' && is_post()) {
        $b=input_data();$allowed=['Received','Work in Progress','Completed','Delivered'];if(!in_array(($b['status']??''),$allowed,true))reply(['error'=>'Invalid status'],400);
        $st=$pdo->prepare('UPDATE orders SET status=? WHERE id=?');$st->execute([$b['status'],(int)($b['id']??0)]);reply(['ok'=>true]);
    }
    if ($action === 'delete_order' && is_post()) {
        $b=input_data();$id=(int)($b['id']??0);if($id<1)reply(['error'=>'Invalid order'],400);
        $pdo->prepare('DELETE FROM payments WHERE order_id=?')->execute([$id]);$pdo->prepare('DELETE FROM order_services WHERE order_id=?')->execute([$id]);$pdo->prepare('DELETE FROM orders WHERE id=?')->execute([$id]);reply(['ok'=>true]);
    }
    if ($action === 'delete_customer' && is_post()) {
        $b=input_data();$id=(int)($b['id']??0);if($id<1)reply(['error'=>'Invalid customer'],400);
        $st=$pdo->prepare('SELECT COUNT(*) FROM orders WHERE customer_id=?');$st->execute([$id]);if((int)$st->fetchColumn()>0)reply(['error'=>'Is customer ke orders hain. Pehle orders delete karein.'],409);
        $pdo->prepare('DELETE FROM customers WHERE id=?')->execute([$id]);reply(['ok'=>true]);
    }
    reply(['error'=>'Unknown action'],404);
} catch (Throwable $e) {
    reply(['error'=>'Server/database error. Check PHP files and table structure.'],500);
}
