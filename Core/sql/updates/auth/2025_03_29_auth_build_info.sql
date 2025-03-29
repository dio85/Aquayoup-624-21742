DROP TABLE IF EXISTS build_info;
CREATE TABLE build_info (
    majorVersion INT NOT NULL,
    minorVersion INT NOT NULL,
    bugfixVersion INT NOT NULL,
    hotfixVersion CHAR(1) NOT NULL DEFAULT ' ',
    build INT PRIMARY KEY
);

INSERT INTO build_info (majorVersion, minorVersion, bugfixVersion, hotfixVersion, build) VALUES
(6, 2, 4, ' ', 21355),
(6, 2, 3, ' ', 20726),
(6, 2, 2, 'a', 20574),
(6, 2, 2, 'a', 20490),
(4, 3, 4, ' ', 15595),
(4, 2, 2, ' ', 14545),
(4, 0, 6, 'a', 13623),
(3, 3, 5, 'a', 13930),
(3, 3, 5, 'a', 12340),
(3, 3, 3, 'a', 11723),
(3, 3, 2, ' ', 11403),
(3, 3, 0, 'a', 11159),
(3, 2, 2, 'a', 10505),
(3, 1, 3, ' ', 9947),
(2, 4, 3, ' ', 8606),
(1, 12, 3, ' ', 6141),
(1, 12, 2, ' ', 6005),
(1, 12, 1, ' ', 5875);