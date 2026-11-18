-- Desenho de producao (NAO integrado ao prototipo, que usa SQLite): usuario do painel com privilegio minimo.
CREATE ROLE painel_app LOGIN PASSWORD :'app_pw';          -- senha passada por variavel, nunca versionada
REVOKE ALL ON ALL TABLES IN SCHEMA public FROM painel_app;
GRANT SELECT ON access_log TO painel_app;                   -- historico: somente leitura
GRANT SELECT (id, email, role, pw_hash, totp_secret) ON users TO painel_app;   -- sem colunas de CPF/nome no login
GRANT INSERT ON approvals TO painel_app;
-- sem DDL, sem DROP, sem acesso a pg_catalog alem do padrao: mesmo com SQLi, o estrago e limitado.
