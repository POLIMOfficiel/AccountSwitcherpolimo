/**
 * @name AccountSwitcher
 * @displayName AccountSwitcher
 * @description Switch between saved accounts with a keybind or a menu. Tokens are always stored encrypted with your password.
 * @version 2.0.0
 * @author l0c4lh057 (original), POLIMOfficiel (fork)
 * @source https://github.com/POLIMOfficiel/AccountSwitcherpolimo
 */

/*
 * Security notes:
 * - No network access and no downloaded code: the plugin no longer needs ZeresPluginLibrary or BugReportHelper.
 * - Tokens are only stored AES-256-GCM encrypted with a key derived (PBKDF2-SHA512) from a password you choose.
 * - The password is only kept in memory until the plugin is stopped or Discord is restarted.
 */

module.exports = class AccountSwitcher {
	constructor(meta) {
		this.meta = meta;
		this.name = meta.name || "AccountSwitcher";
		this.password = null;
		this.menu = null;
		this.crypto = require("crypto");
		this.onKeyDown = this.onKeyDown.bind(this);
		this.onPointer = this.onPointer.bind(this);
		this.closeMenu = this.closeMenu.bind(this);
	}

	// ---------- lifecycle ----------

	start() {
		this.load();
		BdApi.DOM.addStyle(this.name, `
			.accountswitcher-menu { position: fixed; z-index: 10000; display: flex; flex-wrap: wrap; max-width: 360px; padding: 6px; background: #202225; border-radius: 10px; box-shadow: 0 4px 16px rgba(0,0,0,.5); }
			.accountswitcher-item { position: relative; margin: 6px; width: 64px; height: 64px; cursor: pointer; }
			.accountswitcher-item img { width: 64px; height: 64px; border-radius: 50%; }
			.accountswitcher-remove { position: absolute; top: -4px; right: -4px; width: 1.2em; height: 1.2em; line-height: 1.1em; text-align: center; border-radius: 50%; background: #111; border: 2px solid #444; color: #ccc; font-size: 12px; }
			.accountswitcher-panel { color: var(--text-normal, #dcddde); }
			.accountswitcher-panel button { margin: 4px 8px 4px 0; padding: 6px 12px; border: none; border-radius: 4px; background: var(--brand-experiment, #5865f2); color: #fff; cursor: pointer; }
			.accountswitcher-panel input { margin: 4px 0; }
			.accountswitcher-row { display: flex; align-items: center; gap: 8px; margin: 4px 0; }
		`);
		document.addEventListener("mouseup", this.onPointer, true);
		document.addEventListener("click", this.onPointer, true);
		document.addEventListener("keydown", this.onKeyDown, true);
	}

	stop() {
		document.removeEventListener("mouseup", this.onPointer, true);
		document.removeEventListener("click", this.onPointer, true);
		document.removeEventListener("keydown", this.onKeyDown, true);
		this.closeMenu();
		BdApi.DOM.removeStyle(this.name);
		this.password = null;
	}

	// ---------- Discord internals (resolved lazily so Discord updates don't break start()) ----------

	get Webpack() { return BdApi.Webpack; }

	get accountManager() {
		return this.Webpack.getByKeys("loginToken", { searchExports: true })
			|| this.Webpack.getModule(m => m && typeof m.loginToken === "function", { searchExports: true });
	}

	get userStore() {
		return this.Webpack.getStore?.("UserStore")
			|| this.Webpack.getByKeys("getCurrentUser", "getUser");
	}

	get authStore() {
		return this.Webpack.getStore?.("AuthenticationStore")
			|| this.Webpack.getModule(m => m && typeof m.getToken === "function" && typeof m.getId === "function");
	}

	getCurrentUser() {
		return this.userStore?.getCurrentUser?.();
	}

	getAvatarUrl(user) {
		try {
			const url = user.getAvatarURL?.(null, 128, true);
			if (url) return url;
		} catch (e) { /* fall through */ }
		return user.avatar ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png?size=128` : "https://cdn.discordapp.com/embed/avatars/0.png";
	}

	// ---------- settings ----------

	load() {
		const data = BdApi.Data.load(this.name, "settings");
		const valid = data && data.version === 3 && Array.isArray(data.accounts);
		if (data && !valid) {
			// Settings from versions < 2.0.0 used weak or no encryption; they cannot be safely migrated.
			BdApi.UI.showToast("AccountSwitcher: old saved accounts were removed, please save them again.", { type: "warning" });
		}
		this.settings = valid ? data : { version: 3, accounts: [], salt: null, check: null, pluginsToRestart: [] };
		if (!this.settings.salt) {
			this.settings.salt = this.crypto.randomBytes(32).toString("base64");
			this.save();
		}
	}

	save() {
		BdApi.Data.save(this.name, "settings", this.settings);
	}

	// ---------- crypto ----------

	deriveKey(password) {
		return this.crypto.pbkdf2Sync(Buffer.from(password, "utf8"), Buffer.from(this.settings.salt, "base64"), 210000, 32, "sha512");
	}

	encrypt(text, password) {
		const iv = this.crypto.randomBytes(12);
		const cipher = this.crypto.createCipheriv("aes-256-gcm", this.deriveKey(password), iv);
		const enc = Buffer.concat([cipher.update(text, "utf8"), cipher.final()]);
		return [iv, cipher.getAuthTag(), enc].map(b => b.toString("base64")).join(":");
	}

	decrypt(payload, password) {
		const [iv, tag, enc] = payload.split(":").map(p => Buffer.from(p, "base64"));
		const decipher = this.crypto.createDecipheriv("aes-256-gcm", this.deriveKey(password), iv);
		decipher.setAuthTag(tag);
		return Buffer.concat([decipher.update(enc), decipher.final()]).toString("utf8");
	}

	// Resolves with the password (kept in memory) after asking for it, creating it on first use.
	async requirePassword() {
		if (this.password !== null) return this.password;
		const creating = !this.settings.check;
		const pw = await this.promptPassword(creating);
		if (pw === null) throw new Error("cancelled");
		if (creating) {
			this.settings.check = this.encrypt("ok", pw);
			this.save();
		} else {
			try {
				if (this.decrypt(this.settings.check, pw) !== "ok") throw new Error("bad");
			} catch (e) {
				BdApi.UI.showToast("Wrong password", { type: "error" });
				return this.requirePassword();
			}
		}
		this.password = pw;
		return pw;
	}

	promptPassword(creating) {
		return new Promise(resolve => {
			let pw = "", pw2 = "", done = false;
			const finish = v => { if (!done) { done = true; resolve(v); } };
			const h = BdApi.React.createElement;
			const input = (placeholder, set) => h("input", { type: "password", placeholder, onChange: e => set(e.target.value), style: { display: "block", margin: "6px 0", width: "100%" } });
			BdApi.UI.showConfirmationModal(creating ? "Choose a password for your saved accounts" : "Password required",
				h("div", null, input("Password", v => { pw = v; }), creating ? input("Repeat password", v => { pw2 = v; }) : null),
				{
					confirmText: "OK",
					cancelText: "Cancel",
					onConfirm: () => {
						if (!pw || (creating && pw !== pw2)) {
							BdApi.UI.showToast(!pw ? "Password can't be empty" : "Passwords don't match", { type: "error" });
							return finish(null);
						}
						finish(pw);
					},
					onCancel: () => finish(null)
				});
		});
	}

	// ---------- actions ----------

	async saveCurrentAccount() {
		const user = this.getCurrentUser();
		const token = this.authStore?.getToken?.();
		if (!user || !token) return BdApi.UI.showToast("Could not read the current account.", { type: "error" });
		if (this.settings.accounts.some(a => a.id === user.id)) return BdApi.UI.showToast("You already saved this account", { type: "error" });
		const pw = await this.requirePassword().catch(() => null);
		if (pw === null) return;
		this.settings.accounts.push({ id: user.id, name: user.username, avatar: this.getAvatarUrl(user), token: this.encrypt(token, pw) });
		this.save();
		BdApi.UI.showToast(`Saved ${user.username}`, { type: "success" });
	}

	removeAccount(id) {
		this.settings.accounts = this.settings.accounts.filter(a => a.id !== id);
		this.save();
	}

	async login(account) {
		if (account.id === this.getCurrentUser()?.id) return BdApi.UI.showToast(`Already using ${account.name}`, { type: "warning" });
		const manager = this.accountManager;
		if (!manager) return BdApi.UI.showToast("Login module not found (Discord update?).", { type: "error" });
		const pw = await this.requirePassword().catch(() => null);
		if (pw === null) return;
		let token;
		try { token = this.decrypt(account.token, pw); } catch (e) { return BdApi.UI.showToast("Could not decrypt this account.", { type: "error" }); }
		manager.loginToken(token);
		this.settings.pluginsToRestart.forEach(name => {
			if (BdApi.Plugins.isEnabled(name)) {
				BdApi.Plugins.disable(name);
				setTimeout(() => BdApi.Plugins.enable(name), 5000);
			}
		});
	}

	// ---------- UI ----------

	onKeyDown(e) {
		if (!e.altKey || e.ctrlKey || e.metaKey || e.shiftKey || !/^Digit[0-9]$/.test(e.code)) return;
		const n = e.code === "Digit0" ? 9 : Number(e.code.slice(5)) - 1;
		const account = this.settings.accounts[n];
		if (!account) return;
		e.preventDefault();
		this.login(account);
	}

	onPointer(e) {
		if (!((e.type === "mouseup" && e.button === 1) || (e.type === "click" && e.button === 0 && e.altKey))) return;
		const avatar = e.target?.closest?.('[class*="panels"] [class*="avatar"]');
		if (!avatar) return;
		e.preventDefault();
		e.stopPropagation();
		this.openMenu(avatar.getBoundingClientRect());
	}

	openMenu(rect) {
		this.closeMenu();
		if (!this.settings.accounts.length) return BdApi.UI.showToast("No accounts to display", { type: "warning" });
		const menu = document.createElement("div");
		menu.className = "accountswitcher-menu";
		menu.style.left = `${Math.max(rect.left - 5, 5)}px`;
		menu.style.bottom = `${window.innerHeight - rect.top + 8}px`;
		this.settings.accounts.forEach(account => {
			const item = document.createElement("div");
			item.className = "accountswitcher-item";
			item.title = account.name;
			const img = document.createElement("img");
			img.src = account.avatar;
			img.addEventListener("click", () => { this.closeMenu(); this.login(account); });
			const rm = document.createElement("div");
			rm.className = "accountswitcher-remove";
			rm.textContent = "\u00d7";
			rm.addEventListener("click", () => { this.removeAccount(account.id); item.remove(); });
			item.append(img, rm);
			menu.append(item);
		});
		document.body.append(menu);
		this.menu = menu;
		setTimeout(() => document.addEventListener("mousedown", this.closeMenu, true), 0);
	}

	closeMenu(e) {
		if (e && this.menu && this.menu.contains(e.target)) return;
		document.removeEventListener("mousedown", this.closeMenu, true);
		this.menu?.remove();
		this.menu = null;
	}

	getSettingsPanel() {
		const panel = document.createElement("div");
		panel.className = "accountswitcher-panel";
		const render = () => {
			panel.replaceChildren();
			const info = document.createElement("p");
			info.textContent = "Alt+1\u2026Alt+9 / Alt+0 switch to the matching account. Alt+click or middle-click your avatar to open the menu. Tokens are encrypted with your password.";
			panel.append(info);
			this.settings.accounts.forEach((account, i) => {
				const row = document.createElement("div");
				row.className = "accountswitcher-row";
				const label = document.createElement("span");
				label.textContent = `Alt+${(i + 1) % 10}: ${account.name} (${account.id})`;
				const del = document.createElement("button");
				del.textContent = "Remove";
				del.addEventListener("click", () => { this.removeAccount(account.id); render(); });
				row.append(label, del);
				panel.append(row);
			});
			const save = document.createElement("button");
			save.textContent = "Save current account";
			save.addEventListener("click", async () => { await this.saveCurrentAccount(); render(); });
			const logout = document.createElement("button");
			logout.textContent = "Log out to add another account";
			logout.addEventListener("click", () => this.accountManager?.loginToken(""));
			panel.append(save, logout);
			const restartLabel = document.createElement("div");
			restartLabel.textContent = "Plugins to restart when switching (comma separated):";
			const restart = document.createElement("input");
			restart.value = this.settings.pluginsToRestart.join(",");
			restart.addEventListener("change", () => {
				this.settings.pluginsToRestart = restart.value.split(",").map(x => x.trim()).filter(Boolean);
				this.save();
			});
			panel.append(restartLabel, restart);
		};
		render();
		return panel;
	}
};
