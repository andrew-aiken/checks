CREATE SCHEMA test;

-- Table to perform test queries against
CREATE TABLE test.table (
  username varchar(64) NOT NULL PRIMARY KEY,
  age      int         NULL
);

-- Sample data
INSERT INTO test.table (username, age) VALUES ('johndoe', 99);
