// ====== Import Library ======
const bcrypt = require("bcrypt")
const express = require("express")
const session = require("express-session")
const flash = require("connect-flash")
const db = require("better-sqlite3")("E-SLIK.db")
const methodOverride = require("method-override") // <-- TAMBAHAN 1: Import library

db.pragma("journal_mode = WAL")

// ====== Express Setup ======
const app = express()
app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(express.urlencoded({ extended: true }))

// ====== Session Setup ======
app.use(session({
    secret: "rahasia-slik",
    resave: false,
    saveUninitialized: true
}))

// <-- TAMBAHAN 2: Gunakan middleware method-override
// Ini harus ada SEBELUM semua rute Anda
app.use(methodOverride("_method"))

// <-- TAMBAHAN 2: Konfigurasi flash SETELAH session
app.use(flash())

// ====== Middleware Cek Login ======
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/")
    }
    next()
}
// ====== Routes ======

// Login Page
app.get("/", (req, res) => {
    // Ambil flash message 'error' jika ada, lalu kirim ke template
    const errorMsg = req.flash("error")
    res.render("login", { error: errorMsg })
})

// Proses Login
app.post("/login", async (req, res) => {
    const { username, password } = req.body

    if (!username || !password) {
        // Atur flash message
        req.flash("error", "Username dan Password wajib diisi.")
        // Redirect kembali ke halaman login
        return res.redirect("/")
    }

    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username)
    
    if (!user || !(await bcrypt.compare(password, user.password))) {
        // Atur flash message
        req.flash("error", "Username atau Password salah.")
        // Redirect kembali ke halaman login
        return res.redirect("/")
    }

    // Jika berhasil, lanjutkan seperti biasa
    req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role
    }

    if (user.role === "admin") {
        res.redirect("/admin")
    } else {
        res.redirect("/dashboard")
    }
})

// Halaman Admin
app.get("/admin", requireLogin, (req, res) => {
    if (req.session.user.role !== "admin") {
        return res.status(403).send("🚫 Akses ditolak. Bukan admin.")
    }

    const users = db.prepare("SELECT id, username, role FROM users").all()

    // ==> TAMBAHKAN & UBAH BAGIAN INI <==
    res.render("admin", { 
        user: req.session.user,
        users: users,
        successMsg: req.flash("success"), // Ambil pesan sukses
        errorMsg: req.flash("error")      // Ambil pesan error
    })
})

// Proses Tambah User (Versi Ditingkatkan)
app.post("/admin/add-user", requireLogin, async (req, res) => {
    if (req.session.user.role !== "admin") {
        return res.status(403).send("🚫 Akses ditolak. Bukan admin.")
    }
    const { username, password } = req.body
    if (!username || !password) {
        req.flash("error", "Username dan Password wajib diisi.")
        return res.redirect("/admin")
    }

    try {
        // 1. Cek dulu apakah username sudah ada di database
        const existingUser = db.prepare("SELECT id FROM users WHERE username = ?").get(username);

        // 2. Jika ada (hasilnya tidak null), kirim pesan error spesifik
        if (existingUser) {
            req.flash("error", `Gagal menambahkan. Username "${username}" sudah terdaftar.`)
            return res.redirect("/admin")
        }

        // 3. Jika aman (username belum ada), baru hash password dan simpan user baru
        const hashedPassword = await bcrypt.hash(password, 10)
        db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)")
          .run(username, hashedPassword, "user")

        req.flash("success", `User "${username}" berhasil ditambahkan!`)
        res.redirect("/admin")

    } catch (err) {
        console.error("Error saat menambah user:", err)
        req.flash("error", "Terjadi kesalahan pada server. Silakan coba lagi.")
        res.redirect("/admin")
    }
})

// Proses Ubah Password
app.post("/admin/edit-password/:id", requireLogin, async (req, res) => {
    // Pastikan dua baris ini ada dan benar
    const { id } = req.params;
    const { password } = req.body;

    // Tambahkan pengecekan jika password kosong
    if (!password) {
        req.flash("error", "Kolom password baru tidak boleh kosong.");
        return res.redirect("/admin");
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.prepare("UPDATE users SET password = ? WHERE id = ?").run(hashedPassword, id);

        req.flash("success", "Password user berhasil diubah.");
        res.redirect("/admin");

    } catch (err) {
        console.error("Gagal mengubah password, Error:", err); // Log error asli
        req.flash("error", "Gagal mengubah password karena kesalahan server.");
        res.redirect("/admin");
    }
});

// ====== Halaman User Dashboard (Dengan Statistik & Grafik) ======
app.get("/dashboard", requireLogin, (req, res) => {
    if (req.session.user.role !== "user") {
        return res.status(403).send("🚫 Akses ditolak. Bukan user.");
    }

    try {
        const userId = req.session.user.id;
        const periode = req.query.periode || "bulan";

        const today = new Date();
        const todayDate = today.toISOString().split("T")[0];
        const currentMonth = todayDate.substring(0, 7);
        const currentYear = todayDate.substring(0, 4);

        const todayCount = db.prepare(`
            SELECT COUNT(*) as count FROM nasabah 
            WHERE user_id = ? AND tanggalInput = ?
        `).get(userId, todayDate).count;

        const monthCount = db.prepare(`
            SELECT COUNT(*) as count FROM nasabah 
            WHERE user_id = ? AND strftime('%Y-%m', tanggalInput) = ?
        `).get(userId, currentMonth).count;

        const totalCount = db.prepare(`
            SELECT COUNT(*) as count FROM nasabah 
            WHERE user_id = ?
        `).get(userId).count;

        const stats = {
            today: todayCount,
            month: monthCount,
            total: totalCount
        };

        let filterQuery = "";
        let filterValue = "";

        if (periode === "hari") {
            filterQuery = "AND tanggalInput = ?";
            filterValue = todayDate;
        } else if (periode === "minggu") {
            const startOfWeek = new Date(today);
            startOfWeek.setDate(today.getDate() - today.getDay()); 
            const weekStart = startOfWeek.toISOString().split("T")[0];
            filterQuery = "AND tanggalInput >= ?";
            filterValue = weekStart;
        } else if (periode === "bulan") {
            filterQuery = "AND strftime('%Y-%m', tanggalInput) = ?";
            filterValue = currentMonth;
        } else if (periode === "tahun") {
            filterQuery = "AND strftime('%Y', tanggalInput) = ?";
            filterValue = currentYear;
        }

        const salesChartData = db.prepare(`
            SELECT namaSales, COUNT(namaSales) as totalNasabah
            FROM nasabah
            WHERE user_id = ? ${filterQuery}
            GROUP BY namaSales
            ORDER BY totalNasabah DESC
            LIMIT 5
        `).all(userId, filterValue);

        const salesLeastData = db.prepare(`
            SELECT namaSales, COUNT(namaSales) as totalNasabah
            FROM nasabah
            WHERE user_id = ? ${filterQuery}
            GROUP BY namaSales
            ORDER BY totalNasabah ASC
            LIMIT 5
        `).all(userId, filterValue);

        res.render("dashboard", { 
            user: req.session.user,
            stats,
            salesChartData,
            salesLeastData,
            periode
        });

    } catch (err) {
        console.error("Gagal mengambil data statistik:", err);
        res.status(500).send("Gagal memuat dashboard. Terjadi kesalahan pada server.");
    }
});

// Proses Input Nasabah
app.post("/inputnasabah", requireLogin, (req, res) => {
    if (req.session.user.role !== "user") {
        return res.status(403).send("🚫 Akses ditolak. Hanya user yang bisa input data.")
    }
    const { namaNasabah, koderefferal, namaSales } = req.body
    const tanggalInput = new Date().toISOString().split("T")[0]
    const userId = req.session.user.id
    if (!namaNasabah || !koderefferal || !namaSales) {
        return res.send("❌ Semua field wajib diisi")
    }
    try {
        db.prepare("INSERT INTO nasabah (namaNasabah, koderefferal, namaSales, tanggalInput, user_id) VALUES (?, ?, ?, ?, ?)")
          .run(namaNasabah, koderefferal, namaSales, tanggalInput, userId)
        res.redirect("/lihatdata")
    } catch (err) {
        console.error(err)
        res.send("❌ Gagal menyimpan data nasabah")
    }
})

// Halaman Lihat Data
app.get("/lihatdata", requireLogin, (req, res) => {
  if (req.session.user.role !== "user") {
      return res.status(403).send("🚫 Akses ditolak. Bukan user.")
  }
  try {
    const results = db.prepare("SELECT * FROM nasabah WHERE user_id = ? ORDER BY tanggalInput DESC")
                      .all(req.session.user.id)
    res.render("lihatdata", { nasabah: results, user: req.session.user })
  } catch (err) {
    console.error("Error ambil data:", err);
    res.status(500).send("Gagal ambil data");
  }
});

// ====== Rute untuk MENAMPILKAN Halaman Edit Nasabah (GET) ======
app.get("/edit-nasabah/:id", requireLogin, (req, res) => {
    if (req.session.user.role !== "user") {
        return res.status(403).send("🚫 Akses ditolak.");
    }
    try {
        const { id } = req.params;
        const nasabah = db.prepare("SELECT * FROM nasabah WHERE id = ? AND user_id = ?").get(id, req.session.user.id);
        
        if (!nasabah) {
            return res.status(404).send("Data tidak ditemukan atau Anda tidak memiliki akses.");
        }
        
        res.render("edit-nasabah", { nasabah: nasabah });
    } catch (err) {
        console.error("Gagal membuka halaman edit:", err);
        res.status(500).send("Terjadi kesalahan.");
    }
});

// ====== Rute untuk MEMPROSES Perubahan Data Nasabah (POST) ======
app.post("/edit-nasabah/:id", requireLogin, (req, res) => {
    if (req.session.user.role !== "user") {
        return res.status(403).send("🚫 Akses ditolak.");
    }
    try {
        const { id } = req.params;
        const { namaNasabah, koderefferal, namaSales } = req.body;

        db.prepare(
            "UPDATE nasabah SET namaNasabah = ?, koderefferal = ?, namaSales = ? WHERE id = ? AND user_id = ?"
        ).run(namaNasabah, koderefferal, namaSales, id, req.session.user.id);
        
        res.redirect("/lihatdata");
    } catch (err) {
        console.error("Gagal menyimpan perubahan:", err);
        res.status(500).send("Gagal menyimpan perubahan.");
    }
});

// Logout
app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/")
    })
})

// ====== Rute untuk MENGHAPUS Data Nasabah (DELETE) ======
app.delete("/hapus-nasabah/:id", requireLogin, (req, res) => {
    if (req.session.user.role !== "user") {
        return res.status(403).send("🚫 Akses ditolak.");
    }
    try {
        const { id } = req.params;
        const userId = req.session.user.id;
        const result = db.prepare(
            "DELETE FROM nasabah WHERE id = ? AND user_id = ?"
        ).run(id, userId);

        if (result.changes === 0) {
            return res.status(404).send("Data tidak ditemukan atau Anda tidak memiliki izin untuk menghapusnya.");
        }
        console.log(`Data nasabah ID ${id} oleh user ID ${userId} berhasil dihapus.`);
        res.redirect("/lihatdata");

    } catch (err) {
        console.error("Gagal menghapus data nasabah:", err);
        res.status(500).send("Gagal menghapus data nasabah karena terjadi kesalahan server.");
    }
});

// ====== Halaman Top Sales Admin (Statistik & Grafik Keseluruhan) ======
app.get("/top-sales", requireLogin, (req, res) => {
    if (req.session.user.role !== "admin") {
        return res.status(403).send("🚫 Akses ditolak. Halaman ini khusus untuk admin.");
    }

    try {
        const periode = req.query.periode || "bulan";
        const today = new Date();
        const todayDate = today.toISOString().split("T")[0];
        const currentMonth = todayDate.substring(0, 7);
        const currentYear = todayDate.substring(0, 4);
        const startOfWeek = new Date(today);
        startOfWeek.setDate(today.getDate() - today.getDay());
        const weekStartDate = startOfWeek.toISOString().split("T")[0];

        const todayCount = db.prepare(`SELECT COUNT(*) as count FROM nasabah WHERE tanggalInput = ?`).get(todayDate).count;
        const monthCount = db.prepare(`SELECT COUNT(*) as count FROM nasabah WHERE strftime('%Y-%m', tanggalInput) = ?`).get(currentMonth).count;
        const totalCount = db.prepare(`SELECT COUNT(*) as count FROM nasabah`).get().count;
        const weekCount = db.prepare(`SELECT COUNT(*) as count FROM nasabah WHERE tanggalInput >= ?`).get(weekStartDate).count;
        const yearCount = db.prepare(`SELECT COUNT(*) as count FROM nasabah WHERE strftime('%Y', tanggalInput) = ?`).get(currentYear).count;
        const stats = { 
            today: todayCount, 
            week: weekCount,
            month: monthCount, 
            year: yearCount,
            total: totalCount 
        };

        let filterQuery = "";
        let filterValue = "";

        if (periode === "hari") {
            filterQuery = "WHERE nasabah.tanggalInput = ?";
            filterValue = todayDate;
        } else if (periode === "minggu") {
            const startOfWeekFilter = new Date(today);
            startOfWeekFilter.setDate(today.getDate() - today.getDay()); 
            const weekStart = startOfWeekFilter.toISOString().split("T")[0];
            filterQuery = "WHERE nasabah.tanggalInput >= ?";
            filterValue = weekStart;
        } else if (periode === "bulan") {
            filterQuery = "WHERE strftime('%Y-%m', nasabah.tanggalInput) = ?";
            filterValue = currentMonth;
        } else if (periode === "tahun") {
            filterQuery = "WHERE strftime('%Y', nasabah.tanggalInput) = ?";
            filterValue = currentYear;
        }

        const params = filterValue ? [filterValue] : [];
        
        const salesChartData = db.prepare(`
            SELECT 
                nasabah.namaSales, 
                users.username,
                COUNT(nasabah.id) as totalNasabah
            FROM nasabah
            JOIN users ON nasabah.user_id = users.id
            ${filterQuery}
            GROUP BY nasabah.namaSales, users.username
            ORDER BY totalNasabah DESC
            LIMIT 5
        `).all(...params);

        const salesLeastData = db.prepare(`
            SELECT 
                nasabah.namaSales, 
                users.username,
                COUNT(nasabah.id) as totalNasabah
            FROM nasabah
            JOIN users ON nasabah.user_id = users.id
            ${filterQuery}
            GROUP BY nasabah.namaSales, users.username
            ORDER BY totalNasabah ASC
            LIMIT 5
        `).all(...params);

        res.render("top-sales", { 
            user: req.session.user,
            stats,
            salesChartData,
            salesLeastData,
            periode
        });

    } catch (err) {
        console.error("Gagal mengambil data statistik admin:", err);
        res.status(500).send("Gagal memuat halaman statistik. Terjadi kesalahan pada server.");
    }
});

// ====== Jalankan Server ======
app.listen(3000, () => {
    console.log("🚀 Server jalan di http://localhost:3000")
})