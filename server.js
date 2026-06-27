const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const multer = require('multer');
const fs = require('fs');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'votre_cle_secrete_2024';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Dossier uploads
if (!fs.existsSync('./uploads')) fs.mkdirSync('./uploads');
app.use('/uploads', express.static('uploads'));

// Configuration multer
const storage = multer.diskStorage({
    destination: './uploads/',
    filename: (req, file, cb) => {
        cb(null, Date.now() + '-' + file.originalname);
    }
});
const upload = multer({ storage: storage });

// Connexion MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '123456',
    database: 'presence'
});

db.connect(async (err) => {
    if (err) {
        console.error('❌ Erreur MySQL:', err.message);
        return;
    }
    console.log('✅ MySQL connecté');
    
    try {
        const [rows] = await db.promise().query('SELECT id, password FROM users');
        for (const user of rows) {
            if (user.password && user.password.length < 60) {
                const hashedPassword = await bcrypt.hash(user.password, 10);
                await db.promise().query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, user.id]);
            }
        }
        console.log('✅ Mots de passe hashés');
    } catch (error) {}
});

// Middleware d'authentification
const verifierToken = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Accès non autorisé' });
    
    try {
        const decoded = jwt.verify(token.split(' ')[1], SECRET_KEY);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(401).json({ error: 'Token invalide' });
    }
};

// ============ AUTHENTIFICATION ============
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        const [users] = await db.promise().query('SELECT * FROM users WHERE email = ?', [email]);
        if (users.length === 0) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        const user = users[0];
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ error: 'Email ou mot de passe incorrect' });
        const token = jwt.sign(
            { id: user.id, nom: user.nom, email: user.email, role: user.role },
            SECRET_KEY,
            { expiresIn: '24h' }
        );
        res.json({ token, user: { id: user.id, nom: user.nom, email: user.email, role: user.role } });
    } catch (error) {
        res.status(500).json({ error: 'Erreur serveur' });
    }
});

app.get('/api/verify', verifierToken, (req, res) => {
    res.json({ valid: true, user: req.user });
});

// ============ GESTION SÉANCES ============
app.get('/api/seances', verifierToken, (req, res) => {
    db.query('SELECT id, date_seance, heure_debut, heure_fin, description FROM seances ORDER BY date_seance DESC, heure_debut DESC', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/api/seances', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    
    const { date_seance, heure_debut, heure_fin, description } = req.body;
    db.query('INSERT INTO seances (date_seance, heure_debut, heure_fin, description) VALUES (?, ?, ?, ?)',
        [date_seance, heure_debut, heure_fin, description], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: result.insertId, message: 'Séance créée' });
        });
});

app.delete('/api/seances/:id', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    
    db.query('DELETE FROM presences WHERE seance_id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        db.query('DELETE FROM seances WHERE id = ?', [req.params.id], (err) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ message: 'Séance supprimée' });
        });
    });
});

// ============ GESTION ÉTUDIANTS ============
app.get('/api/etudiants', verifierToken, (req, res) => {
    db.query('SELECT * FROM etudiants ORDER BY nom', (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/api/etudiants', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    
    const { nom, prenom, matricule } = req.body;
    db.query('INSERT INTO etudiants (nom, prenom, matricule) VALUES (?, ?, ?)',
        [nom, prenom, matricule], (err, result) => {
            if (err) return res.status(500).json({ error: err.message });
            res.json({ id: result.insertId, message: 'Étudiant ajouté' });
        });
});

app.delete('/api/etudiants/:id', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    
    db.query('DELETE FROM etudiants WHERE id = ?', [req.params.id], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Étudiant supprimé' });
    });
});

// ============ GESTION PRÉSENCES ============
app.get('/api/presences/:seanceId', verifierToken, (req, res) => {
    const seanceId = req.params.seanceId;
    db.query(`
        SELECT e.id, e.nom, e.prenom, e.matricule, 
               COALESCE(p.present, 0) as present, p.justificatif, p.justificatif_valide, p.id as presence_id
        FROM etudiants e
        LEFT JOIN presences p ON e.id = p.etudiant_id AND p.seance_id = ?
        ORDER BY e.nom
    `, [seanceId], (err, results) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json(results);
    });
});

app.post('/api/presences', verifierToken, (req, res) => {
    const { seance_id, presences } = req.body;
    
    if (!presences || presences.length === 0) {
        return res.json({ message: 'Aucune présence à enregistrer' });
    }
    
    let completed = 0;
    let hasError = false;
    
    presences.forEach(p => {
        db.query(`
            INSERT INTO presences (etudiant_id, seance_id, present) 
            VALUES (?, ?, ?) 
            ON DUPLICATE KEY UPDATE present = ?
        `, [p.etudiant_id, seance_id, p.present, p.present], (err) => {
            if (err) hasError = true;
            completed++;
            if (completed === presences.length) {
                if (hasError) {
                    res.status(500).json({ error: 'Erreur lors de l\'enregistrement' });
                } else {
                    res.json({ message: 'Présences enregistrées' });
                }
            }
        });
    });
});

app.put('/api/presences/modifier', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    
    const { seance_id, etudiant_id, present, justificatif_valide } = req.body;
    
    db.query(`
        INSERT INTO presences (etudiant_id, seance_id, present, justificatif_valide)
        VALUES (?, ?, ?, ?)
        ON DUPLICATE KEY UPDATE present = ?, justificatif_valide = ?
    `, [etudiant_id, seance_id, present, justificatif_valide, present, justificatif_valide], (err) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Présence modifiée' });
    });
});

// Upload de justificatif
app.post('/api/upload-justificatif', verifierToken, upload.single('fichier'), (req, res) => {
    const { presence_id, etudiant_id, seance_id, motif } = req.body;
    const filename = req.file.filename;
    
    db.query(`
        UPDATE presences 
        SET justificatif = ?, justificatif_valide = 0, date_justificatif = CURDATE(), motif_absence = ?
        WHERE id = ? OR (etudiant_id = ? AND seance_id = ?)
    `, [filename, motif, presence_id, etudiant_id, seance_id], (err, result) => {
        if (err) return res.status(500).json({ error: err.message });
        res.json({ message: 'Justificatif uploadé', fichier: filename });
    });
});

// ============ GESTION DES JUSTIFICATIFS ============
app.get('/api/justificatifs/en-attente', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    db.query(`
        SELECT p.id as presence_id, e.nom, e.prenom, e.matricule, s.date_seance, s.description as seance, p.justificatif, p.date_justificatif, p.motif_absence
        FROM presences p JOIN etudiants e ON p.etudiant_id = e.id JOIN seances s ON p.seance_id = s.id
        WHERE p.present = 0 AND p.justificatif IS NOT NULL AND (p.justificatif_valide = 0 OR p.justificatif_valide IS NULL)
        ORDER BY p.date_justificatif DESC
    `, (err, results) => { if (err) return res.status(500).json({ error: err.message }); res.json(results); });
});

app.get('/api/justificatifs/valides', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    db.query(`
        SELECT p.id as presence_id, e.nom, e.prenom, e.matricule, s.date_seance, s.description as seance, p.justificatif, p.date_justificatif, p.motif_absence
        FROM presences p JOIN etudiants e ON p.etudiant_id = e.id JOIN seances s ON p.seance_id = s.id
        WHERE p.present = 0 AND p.justificatif IS NOT NULL AND p.justificatif_valide = 1
        ORDER BY p.date_justificatif DESC
    `, (err, results) => { if (err) return res.status(500).json({ error: err.message }); res.json(results); });
});

app.get('/api/justificatifs/rejetes', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    db.query(`
        SELECT p.id as presence_id, e.nom, e.prenom, e.matricule, s.date_seance, s.description as seance, p.justificatif, p.date_justificatif, p.motif_absence
        FROM presences p JOIN etudiants e ON p.etudiant_id = e.id JOIN seances s ON p.seance_id = s.id
        WHERE p.present = 0 AND p.justificatif IS NOT NULL AND p.justificatif_valide = 2
        ORDER BY p.date_justificatif DESC
    `, (err, results) => { if (err) return res.status(500).json({ error: err.message }); res.json(results); });
});

app.put('/api/justificatifs/:id/traiter', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    const { valide } = req.body;
    const presenceId = req.params.id;
    
    db.query('SELECT justificatif FROM presences WHERE id = ?', [presenceId], (err, results) => {
        if (err || results.length === 0) return res.status(500).json({ error: 'Justificatif non trouvé' });
        const filename = results[0].justificatif;
        
        if (valide === 1) {
            db.query('UPDATE presences SET justificatif_valide = 1, date_traitement = NOW() WHERE id = ?', [presenceId], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Justificatif validé', valide: 1 });
            });
        } else {
            const filePath = path.join(__dirname, 'uploads', filename);
            if (fs.existsSync(filePath)) fs.unlinkSync(filePath, () => {});
            db.query('UPDATE presences SET justificatif_valide = 2, date_traitement = NOW() WHERE id = ?', [presenceId], (err) => {
                if (err) return res.status(500).json({ error: err.message });
                res.json({ message: 'Justificatif rejeté', valide: 2 });
            });
        }
    });
});

// ============ STATISTIQUES ============
app.get('/api/stats/seances-completes', verifierToken, (req, res) => {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Accès refusé' });
    const { date_debut, date_fin } = req.query;
    let sql = `SELECT s.id, s.date_seance, s.description, (SELECT COUNT(*) FROM etudiants) as total_etudiants FROM seances s`;
    if (date_debut && date_fin) sql += ` WHERE s.date_seance BETWEEN '${date_debut}' AND '${date_fin}'`;
    sql += ` ORDER BY s.date_seance DESC`;
    
    db.query(sql, (err, seances) => {
        if (err) return res.status(500).json({ error: err.message });
        if (seances.length === 0) return res.json([]);
        let resultats = [], compteur = 0;
        seances.forEach(seance => {
            db.query(`SELECT e.id, COALESCE(p.present, 0) as present, p.justificatif_valide FROM etudiants e LEFT JOIN presences p ON e.id = p.etudiant_id AND p.seance_id = ? ORDER BY e.nom`, [seance.id], (err, etudiants) => {
                if (err) etudiants = [];
                const presents = etudiants.filter(e => e.present === 1).length;
                const absJ = etudiants.filter(e => e.present === 0 && e.justificatif_valide === 1).length;
                const absNJ = etudiants.filter(e => e.present === 0 && (e.justificatif_valide === 0 || e.justificatif_valide === null)).length;
                resultats.push({
                    id: seance.id, date_seance: seance.date_seance, description: seance.description,
                    total_etudiants: seance.total_etudiants, presents, absents_justifies: absJ, absents_non_justifies: absNJ,
                    taux_presence: seance.total_etudiants > 0 ? ((presents / seance.total_etudiants) * 100).toFixed(1) : 0
                });
                compteur++;
                if (compteur === seances.length) res.json(resultats);
            });
        });
    });
});

app.get('/api/stats', verifierToken, (req, res) => {
    db.query(`SELECT (SELECT COUNT(*) FROM etudiants) as total_etudiants, (SELECT COUNT(*) FROM seances) as total_seances, SUM(CASE WHEN present = 1 THEN 1 ELSE 0 END) as total_presents, SUM(CASE WHEN present = 0 THEN 1 ELSE 0 END) as total_absents FROM presences`,
        (err, results) => { if (err) return res.status(500).json({ error: err.message }); res.json(results[0] || {}); });
});

// ============ PAGES ============
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/enseignant', (req, res) => res.sendFile(path.join(__dirname, 'enseignant.html')));
app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'admin.html')));

// ============ DÉMARRAGE ============
app.listen(PORT, () => {
    console.log(`\n🚀 Serveur démarré sur http://localhost:${PORT}`);
    console.log(`🔐 Admin: admin@presence.com / admin123`);
    console.log(`🔐 Enseignant: prof@presence.com / enseignant123\n`);
});
