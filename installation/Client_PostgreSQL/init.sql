CREATE ROLE admin1 SUPERUSER CREATEDB INHERIT;
CREATE DATABASE admindb1 OWNER admin1;
\c admindb1;
CREATE TABLE table1 (id int PRIMARY KEY, name VARCHAR(50));
INSERT INTO table1 VALUES (1, 'toto');
INSERT INTO table1 VALUES (2, 'titi');

GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO admin1 ;