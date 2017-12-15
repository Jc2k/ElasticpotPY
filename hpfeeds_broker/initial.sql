CREATE TABLE logs (
    id integer primary key autoincrement,
    data TEXT
);

CREATE TABLE stats (
    id integer primary key autoincrement,
    ak TEXT,
    uid TEXT,
    data TEXT
);

CREATE TABLE authkeys (
    id integer primary key autoincrement,
    owner TEXT,
    ident TEXT,
    secret TEXT,
    pubchans TEXT,
    subchans TEXT
);

INSERT INTO authkeys (owner, ident, secret, pubchans, subchans) VALUES (
    'elasticpot',
    'elasticpot',
    'elasticpot',
    '["elasticpot"]',
    '[]'
);
