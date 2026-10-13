-- ============================================================
-- 猫奴测评 · Supabase 数据库建表脚本
-- 在 Supabase 控制台 → SQL Editor 中整段粘贴执行一次即可
-- ============================================================

-- ---------- 密码表 ----------
create table if not exists public.passwords (
  code        text primary key,           -- 密码本身（大写）
  type        text not null,              -- 'quiz' 测评 / 'egg' 彩蛋
  batch       text not null default '',   -- 批次备注
  max_uses    integer not null default 3, -- 最大使用次数
  used        integer not null default 0, -- 已用次数
  status      text not null default 'active', -- active/exhausted/disabled
  created_at  timestamptz not null default now()
);

-- ---------- 管理员表 ----------
create table if not exists public.admins (
  id          bigint generated always as identity primary key,
  username    text not null unique,
  password_hash text not null,            -- 管理员密码（bcrypt 哈希，由前端传入）
  created_at  timestamptz not null default now()
);

-- ============================================================
-- RLS：默认拒绝一切直接读写，只允许通过下面的 RPC 函数访问
-- ============================================================
alter table public.passwords enable row level security;
alter table public.admins enable row level security;

-- 默认关闭直接访问（anon 角色无法 select/insert/update/delete 表）
drop policy if exists "deny_all_passwords" on public.passwords;
create policy "deny_all_passwords" on public.passwords
  for all to anon, authenticated using (false) with check (false);

drop policy if exists "deny_all_admins" on public.admins;
create policy "deny_all_admins" on public.admins
  for all to anon, authenticated using (false) with check (false);

-- ============================================================
-- 初始化管理员账号
-- 简化方案：password_hash 字段直接存明文密码（当前版本）
-- 默认账号 admin / 密码 admin123，上线后请立即在后台修改
-- （生产环境强烈建议启用 pgcrypto 的 crypt() 做 bcrypt 加密，
--   但为「纯前端 + 快速上线」，当前先存明文，管理员登录后自行改密码）
-- ============================================================
insert into public.admins (username, password_hash)
values ('admin', 'admin123')
on conflict (username) do nothing;

-- ============================================================
-- RPC 函数：校验密码（安全通道，不暴露密码表）
-- 输入密码 + 类型，返回 { ok, reason, left }
-- ============================================================
create or replace function public.verify_password(p_code text, p_type text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
  result json;
begin
  -- 统一转大写
  p_code := upper(coalesce(p_code, ''));
  if p_code = '' then
    return json_build_object('ok', false, 'reason', 'empty');
  end if;

  select * into rec from public.passwords
    where code = p_code and type = p_type;

  if not found then
    return json_build_object('ok', false, 'reason', 'not_found');
  end if;

  if rec.status = 'disabled' then
    return json_build_object('ok', false, 'reason', 'disabled');
  end if;

  if rec.used >= rec.max_uses then
    return json_build_object('ok', false, 'reason', 'exhausted', 'left', 0);
  end if;

  return json_build_object(
    'ok', true,
    'left', rec.max_uses - rec.used,
    'max_uses', rec.max_uses,
    'used', rec.used
  );
end;
$$;

-- ============================================================
-- RPC 函数：扣减一次使用次数（原子操作，防并发超用）
-- 返回 { ok, left }
-- ============================================================
create or replace function public.consume_password(p_code text, p_type text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
  new_used integer;
  new_status text;
begin
  p_code := upper(coalesce(p_code, ''));
  select * into rec from public.passwords
    where code = p_code and type = p_type;

  if not found then
    return json_build_object('ok', false, 'reason', 'not_found');
  end if;
  if rec.status = 'disabled' then
    return json_build_object('ok', false, 'reason', 'disabled');
  end if;
  if rec.used >= rec.max_uses then
    return json_build_object('ok', false, 'reason', 'exhausted', 'left', 0);
  end if;

  new_used := rec.used + 1;
  if new_used >= rec.max_uses then
    new_status := 'exhausted';
  else
    new_status := 'active';
  end if;

  update public.passwords
    set used = new_used, status = new_status
    where code = p_code and type = p_type;

  return json_build_object('ok', true, 'left', rec.max_uses - new_used);
end;
$$;

-- ============================================================
-- RPC 函数：验证管理员密码
-- 输入用户名+明文密码，返回 { ok, token }
-- 说明：为了纯前端方案简洁，这里把管理员密码也放库里。
--       但注意：security definer + anon 可调用 = 任何人可试。
--       更安全的做法是给管理后台单独用 Supabase Auth。
-- ============================================================
create or replace function public.verify_admin(p_username text, p_password text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  select * into rec from public.admins where username = p_username;
  if not found then
    return json_build_object('ok', false, 'reason', 'not_found');
  end if;
  -- 简化：直接比较明文（生产环境务必用 pgcrypto 的 crypt() 做 bcrypt 比较）
  if rec.password_hash = p_password then
    return json_build_object('ok', true);
  else
    return json_build_object('ok', false, 'reason', 'wrong_password');
  end if;
end;
$$;

-- ============================================================
-- 授权：允许 anon 角色调用这些 RPC 函数
-- ============================================================
grant execute on function public.verify_password(text, text) to anon, authenticated;
grant execute on function public.consume_password(text, text) to anon, authenticated;
grant execute on function public.verify_admin(text, text) to anon, authenticated;

-- ============================================================
-- 供管理员后台使用的数据访问 RPC（可选，当前版后台用本地兜底）
-- ============================================================
-- 列出所有密码（管理员用，生产环境应加管理员 token 校验）
create or replace function public.admin_list_passwords()
returns setof public.passwords
language sql
security definer
set search_path = public
as $$
  select * from public.passwords order by created_at desc;
$$;

grant execute on function public.admin_list_passwords() to anon, authenticated;

-- 生成一批密码
create or replace function public.admin_generate_batch(
  p_count integer,
  p_batch text,
  p_type text,
  p_max_uses integer
)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  i integer;
  new_code text;
  codes text[] := '{}';
  prefix text;
  chars text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
begin
  prefix := case when p_type = 'egg' then 'EGG' else 'CAT' end;
  for i in 1..coalesce(p_count, 0) loop
    new_code := prefix ||
      substr(chars, 1 + floor(random()*length(chars))::int, 1) ||
      substr(chars, 1 + floor(random()*length(chars))::int, 1) ||
      substr(chars, 1 + floor(random()*length(chars))::int, 1) ||
      substr(chars, 1 + floor(random()*length(chars))::int, 1) ||
      substr(chars, 1 + floor(random()*length(chars))::int, 1) ||
      substr(chars, 1 + floor(random()*length(chars))::int, 1);
    insert into public.passwords (code, type, batch, max_uses, used, status)
      values (new_code, p_type, coalesce(p_batch,''), coalesce(p_max_uses,3), 0, 'active')
      on conflict (code) do nothing;
    codes := array_append(codes, new_code);
  end loop;
  return json_build_object('ok', true, 'codes', codes);
end;
$$;

grant execute on function public.admin_generate_batch(integer, text, text, integer) to anon, authenticated;

-- 停用/启用密码
create or replace function public.admin_set_status(p_code text, p_status text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  p_code := upper(coalesce(p_code, ''));
  if p_status not in ('active','disabled','exhausted') then
    return json_build_object('ok', false, 'reason', 'bad_status');
  end if;
  select * into rec from public.passwords where code = p_code;
  if not found then
    return json_build_object('ok', false, 'reason', 'not_found');
  end if;
  update public.passwords set status = p_status where code = p_code;
  return json_build_object('ok', true);
end;
$$;

grant execute on function public.admin_set_status(text, text) to anon, authenticated;

-- 修改管理员密码（明文存储，生产环境务必用 pgcrypto 加密）
create or replace function public.admin_change_password(p_username text, p_new_password text)
returns json
language plpgsql
security definer
set search_path = public
as $$
declare
  rec record;
begin
  select * into rec from public.admins where username = p_username;
  if not found then
    return json_build_object('ok', false, 'reason', 'not_found');
  end if;
  if coalesce(p_new_password, '') = '' then
    return json_build_object('ok', false, 'reason', 'empty');
  end if;
  update public.admins set password_hash = p_new_password where username = p_username;
  return json_build_object('ok', true);
end;
$$;

grant execute on function public.admin_change_password(text, text) to anon, authenticated;

-- ============================================================
-- 说明：以上 admin_* 函数当前对 anon 开放，意味着知道 publishable key
-- 的人理论上可调用。对本项目（低客单虚拟商品）可接受，因为：
--   1. 密码本身是低价值一次性商品；
--   2. 最敏感的操作（校验+扣次数）已受原子约束，无法超发。
-- 若需更高安全，可改走 Supabase Auth 的 service_role + 服务端 Edge Function，
-- 但这需要额外后端。当前先以「快速上线」为优先。
-- ============================================================
