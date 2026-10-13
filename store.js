/* ============================================================
 * 猫奴测评 · 共享数据层（Supabase 后端）
 * 测评端 index.html 与后台 admin.html 共用
 *
 * 通过 Supabase REST API 调用 RPC 函数（安全通道，不暴露密码表）
 * 所有接口均为异步（返回 Promise）。
 *
 * 配置项：SUPABASE_URL / SUPABASE_KEY 为公开的 publishable key，
 * 可放心放前端。
 * ============================================================ */
(function (global) {
  // ---- 配置：填入你的 Supabase 项目信息 ----
  const SUPABASE_URL = "https://megnwkaglnlndzmordnt.supabase.co";
  const SUPABASE_KEY = "sb_publishable_" + "hyWc7LxFA9K90_F2JZw1mw_gCMnIWg0";

  // 管理员用户名（默认 admin）
  const ADMIN_USERNAME = "admin";

  // ---- REST 调用封装 ----
  async function rpc(fnName, args) {
    const url = SUPABASE_URL + "/rest/v1/rpc/" + fnName;
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
      },
      body: JSON.stringify(args || {}),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error("RPC " + fnName + " 失败: " + res.status + " " + txt);
    }
    return res.json();
  }

  /* ---------- 密码校验（异步） ---------- */
  // 返回 { ok, reason, left, max_uses, used }
  function verify(code, type) {
    return rpc("verify_password", { p_code: code, p_type: type });
  }

  /* 扣减一次使用次数（异步） */
  function consume(code, type) {
    return rpc("consume_password", { p_code: code, p_type: type });
  }

  /* 管理员校验（异步），返回 { ok, reason } */
  function verifyAdmin(password) {
    return rpc("verify_admin", { p_username: ADMIN_USERNAME, p_password: password });
  }

  /* 管理员：列出所有密码（异步），返回数组 */
  async function adminListPasswords() {
    const url = SUPABASE_URL + "/rest/v1/rpc/admin_list_passwords";
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
      },
      body: "{}",
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      console.warn("admin_list_passwords 失败", res.status, txt);
      return [];
    }
    return res.json();
  }

  /* 管理员：生成一批密码（异步），返回 { ok, codes } */
  function generateBatch(count, batch, type, maxUses) {
    return rpc("admin_generate_batch", {
      p_count: count,
      p_batch: batch,
      p_type: type,
      p_max_uses: maxUses,
    });
  }

  /* 管理员：修改管理员密码（异步） */
  function changeAdmin(newPassword) {
    return rpc("admin_change_password", { p_username: ADMIN_USERNAME, p_new_password: newPassword });
  }

  /* 管理员：停用/启用密码（异步） */
  async function setStatus(code, status) {
    const url = SUPABASE_URL + "/rest/v1/rpc/admin_set_status";
    const res = await fetch(url, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": SUPABASE_KEY,
        "Authorization": "Bearer " + SUPABASE_KEY,
      },
      body: JSON.stringify({ p_code: code, p_status: status }),
    });
    if (!res.ok) {
      const txt = await res.text().catch(() => "");
      throw new Error("admin_set_status 失败: " + res.status + " " + txt);
    }
    return res.json();
  }

  /* 状态文案 */
  function statusText(s) {
    return { active: "可用", exhausted: "已用完", disabled: "已停用" }[s] || s;
  }

  global.CatQuizStore = {
    SUPABASE_URL,
    SUPABASE_KEY,
    ADMIN_USERNAME,
    // 异步接口
    verify,
    consume,
    verifyAdmin,
    adminListPasswords,
    generateBatch,
    setStatus,
    changeAdmin,
    statusText,
  };
})(typeof window !== "undefined" ? window : this);
