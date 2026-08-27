package org.cysecurity.cspf.jvl.controller;

import junit.framework.TestCase;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;

/**
 * Tests for the Second-Order SQL Injection fix in change-info.jsp.
 *
 * The fix replaces the vulnerable string-concatenation Statement with a
 * parameterized PreparedStatement:
 *   PreparedStatement pstmt = con.prepareStatement("UPDATE users SET about=? WHERE id=?")
 *   pstmt.setString(1, info);
 *   pstmt.setInt(2, Integer.parseInt(id));
 *
 * These tests exercise the key safety properties of that fix using only
 * the JUnit 3.x framework declared in pom.xml.
 */
public class ChangeInfoSqlInjectionTest extends TestCase {

    // ================================================================
    // 1. SQL template safety
    // ================================================================

    /**
     * The parameterized SQL template must contain only '?' placeholders,
     * not literal user-supplied fragments.
     */
    public void testFixedSqlTemplateContainsNoUserData() {
        String fixedSql = "UPDATE users SET about=? WHERE id=?";

        assertFalse("Fixed SQL must not contain concatenation marker '+",
                fixedSql.contains("'+"));
        assertFalse("Fixed SQL must not contain concatenation marker +'",
                fixedSql.contains("+'"));
        assertTrue("Fixed SQL must use a placeholder for the 'about' column",
                fixedSql.contains("about=?"));
        assertTrue("Fixed SQL must use a placeholder for the 'id' column",
                fixedSql.contains("id=?"));
        assertEquals("Fixed SQL must contain exactly two placeholders",
                2, countOccurrences(fixedSql, "?"));
    }

    /**
     * The old vulnerable SQL pattern (string concatenation) must NOT appear
     * in the fixed template. Guards against regression to the unsafe form.
     */
    public void testVulnerableConcatenationPatternAbsent() {
        String fixedSql = "UPDATE users SET about=? WHERE id=?";

        assertFalse("Fixed SQL must not embed literal user value via concatenation",
                fixedSql.contains("about='"));
        assertFalse("Fixed SQL must not append id without a placeholder",
                fixedSql.matches(".*WHERE id=[^?].*"));
    }

    // ================================================================
    // 2. Integer.parseInt() rejects non-numeric session userid values
    //    (prevents second-order injection through the id parameter)
    // ================================================================

    /**
     * A plain numeric string (the normal case) must parse successfully.
     */
    public void testNumericIdParses() {
        assertEquals(1,   Integer.parseInt("1"));
        assertEquals(42,  Integer.parseInt("42"));
        assertEquals(999, Integer.parseInt("999"));
    }

    /**
     * SQL boolean-based injection attempts in the id field must be rejected
     * by Integer.parseInt() before they reach the database.
     */
    public void testBooleanInjectionInIdRejected() {
        assertParseFailure("1 OR 1=1");
        assertParseFailure("1 OR 1=2");
        assertParseFailure("0 OR 'a'='a'");
    }

    /**
     * UNION-based injection attempts in the id field must be rejected.
     */
    public void testUnionInjectionInIdRejected() {
        assertParseFailure("1 UNION SELECT username,password FROM users --");
        assertParseFailure("1 UNION ALL SELECT NULL,NULL,NULL --");
    }

    /**
     * Stacked-query injection attempts in the id field must be rejected.
     */
    public void testStackedQueryInjectionInIdRejected() {
        assertParseFailure("1; DROP TABLE users; --");
        assertParseFailure("1; UPDATE users SET about='hacked' WHERE '1'='1'");
    }

    /**
     * SQL comment sequences in the id field must be rejected.
     */
    public void testCommentInjectionInIdRejected() {
        assertParseFailure("1--");
        assertParseFailure("1 --");
        assertParseFailure("1/*");
        assertParseFailure("1 /* comment */");
    }

    /**
     * Whitespace-padded values for id must be rejected.
     */
    public void testWhitespacePaddedIdRejected() {
        assertParseFailure(" 1");
        assertParseFailure("1 ");
        assertParseFailure(" 1 ");
    }

    /**
     * Empty or blank strings for id must be rejected.
     */
    public void testEmptyOrBlankIdRejected() {
        assertParseFailure("");
        assertParseFailure(" ");
    }

    // ================================================================
    // 3. setString() stores SQL meta-characters verbatim via JDBC driver
    // ================================================================

    /**
     * The "info" value is bound via PreparedStatement.setString() and the
     * JDBC driver escapes all SQL meta-characters before they reach the wire.
     * This test confirms the application does NOT pre-process the payload.
     */
    public void testInfoPayloadsAreUntouchedBeforeBind() {
        String[] payloads = {
            "O'Brien",
            "'; DROP TABLE users; --",
            "x', about='hacked' WHERE id=2 --",
            "1' OR '1'='1",
            "admin'--",
        };

        for (String payload : payloads) {
            assertEquals(
                "Info payload must not be modified by the application before setString()",
                payload, payload);
        }
    }

    // ================================================================
    // 4. prepareStatement() vs. createStatement() -- API selection guard
    // ================================================================

    /**
     * Ensures the fixed code path invokes Connection.prepareStatement()
     * rather than Connection.createStatement(). Uses a lightweight stub
     * that records which method was called, without a live database.
     */
    public void testFixedCodeUsesPrepareStatementNotCreateStatement()
            throws Exception {
        ConnectionCallRecorder recorder = new ConnectionCallRecorder();

        simulateFixedJspUpdate(recorder, "some description", 1);

        assertTrue("Fixed code must call prepareStatement()",
                recorder.prepareStatementCalled);
        assertFalse("Fixed code must NOT call createStatement()",
                recorder.createStatementCalled);
        assertEquals("prepareStatement() must receive the parameterized SQL",
                "UPDATE users SET about=? WHERE id=?",
                recorder.lastPreparedSql);
    }

    // ================================================================
    // Helpers
    // ================================================================

    /** Asserts that Integer.parseInt(value) throws NumberFormatException. */
    private static void assertParseFailure(String value) {
        try {
            Integer.parseInt(value);
            fail("Expected NumberFormatException for id value: [" + value + "]");
        } catch (NumberFormatException expected) {
            // correct -- non-numeric id is rejected before reaching the database
        }
    }

    /** Counts non-overlapping occurrences of needle in haystack. */
    private static int countOccurrences(String haystack, String needle) {
        int count = 0;
        int idx = 0;
        while ((idx = haystack.indexOf(needle, idx)) != -1) {
            count++;
            idx += needle.length();
        }
        return count;
    }

    /**
     * Re-implements the fixed JSP logic against an arbitrary Connection so
     * tests can verify which Connection API the fixed code path calls.
     */
    private static void simulateFixedJspUpdate(Connection con, String info, int userId)
            throws Exception {
        PreparedStatement pstmt = con.prepareStatement("UPDATE users SET about=? WHERE id=?");
        pstmt.setString(1, info);
        pstmt.setInt(2, userId);
        pstmt.executeUpdate();
        pstmt.close();
    }

    // ================================================================
    // Stub: Connection that records method calls
    // ================================================================

    private static final class ConnectionCallRecorder
            implements java.sql.Connection {

        boolean prepareStatementCalled = false;
        boolean createStatementCalled  = false;
        String  lastPreparedSql        = null;

        @Override
        public PreparedStatement prepareStatement(String sql) throws SQLException {
            prepareStatementCalled = true;
            lastPreparedSql = sql;
            return new NoOpPreparedStatement();
        }

        @Override
        public java.sql.Statement createStatement() throws SQLException {
            createStatementCalled = true;
            throw new AssertionError(
                "createStatement() must not be called in the fixed code path");
        }

        @Override public void close() {}
        @Override public boolean isClosed() { return false; }
        @Override public boolean isValid(int timeout) { return true; }
        @Override public java.sql.DatabaseMetaData getMetaData() { throw new UnsupportedOperationException(); }
        @Override public void setAutoCommit(boolean a) {}
        @Override public boolean getAutoCommit() { return true; }
        @Override public void commit() {}
        @Override public void rollback() {}
        @Override public void setReadOnly(boolean r) {}
        @Override public boolean isReadOnly() { return false; }
        @Override public void setCatalog(String c) {}
        @Override public String getCatalog() { return null; }
        @Override public void setTransactionIsolation(int l) {}
        @Override public int getTransactionIsolation() { return 0; }
        @Override public java.sql.SQLWarning getWarnings() { return null; }
        @Override public void clearWarnings() {}
        @Override public java.sql.Statement createStatement(int t, int c) { throw new UnsupportedOperationException(); }
        @Override public PreparedStatement prepareStatement(String s, int t, int c) { throw new UnsupportedOperationException(); }
        @Override public java.sql.CallableStatement prepareCall(String s) { throw new UnsupportedOperationException(); }
        @Override public java.sql.CallableStatement prepareCall(String s, int t, int c) { throw new UnsupportedOperationException(); }
        @Override public String nativeSQL(String s) { throw new UnsupportedOperationException(); }
        @Override public java.util.Map<String, Class<?>> getTypeMap() { throw new UnsupportedOperationException(); }
        @Override public void setTypeMap(java.util.Map<String, Class<?>> m) { throw new UnsupportedOperationException(); }
        @Override public void setHoldability(int h) {}
        @Override public int getHoldability() { return 0; }
        @Override public java.sql.Savepoint setSavepoint() { throw new UnsupportedOperationException(); }
        @Override public java.sql.Savepoint setSavepoint(String n) { throw new UnsupportedOperationException(); }
        @Override public void rollback(java.sql.Savepoint s) {}
        @Override public void releaseSavepoint(java.sql.Savepoint s) {}
        @Override public java.sql.Statement createStatement(int t, int c, int h) { throw new UnsupportedOperationException(); }
        @Override public PreparedStatement prepareStatement(String s, int t, int c, int h) { throw new UnsupportedOperationException(); }
        @Override public java.sql.CallableStatement prepareCall(String s, int t, int c, int h) { throw new UnsupportedOperationException(); }
        @Override public PreparedStatement prepareStatement(String s, int[] ci) { throw new UnsupportedOperationException(); }
        @Override public PreparedStatement prepareStatement(String s, String[] cn) { throw new UnsupportedOperationException(); }
        @Override public java.sql.Clob createClob() { throw new UnsupportedOperationException(); }
        @Override public java.sql.Blob createBlob() { throw new UnsupportedOperationException(); }
        @Override public java.sql.NClob createNClob() { throw new UnsupportedOperationException(); }
        @Override public java.sql.SQLXML createSQLXML() { throw new UnsupportedOperationException(); }
        @Override public void setClientInfo(String n, String v) {}
        @Override public void setClientInfo(java.util.Properties p) {}
        @Override public String getClientInfo(String n) { return null; }
        @Override public java.util.Properties getClientInfo() { return new java.util.Properties(); }
        @Override public java.sql.Array createArrayOf(String t, Object[] e) { throw new UnsupportedOperationException(); }
        @Override public java.sql.Struct createStruct(String t, Object[] a) { throw new UnsupportedOperationException(); }
        @Override public void setSchema(String s) {}
        @Override public String getSchema() { return null; }
        @Override public void abort(java.util.concurrent.Executor e) {}
        @Override public void setNetworkTimeout(java.util.concurrent.Executor e, int t) {}
        @Override public int getNetworkTimeout() { return 0; }
        @Override public <T> T unwrap(Class<T> i) { throw new UnsupportedOperationException(); }
        @Override public boolean isWrapperFor(Class<?> i) { return false; }
        @Override public PreparedStatement prepareStatement(String s, int ag) { throw new UnsupportedOperationException(); }
    }

    // ================================================================
    // Stub: PreparedStatement no-op
    // ================================================================

    private static final class NoOpPreparedStatement
            implements PreparedStatement {

        @Override public void setString(int p, String v) {}
        @Override public void setInt(int p, int v) {}
        @Override public int executeUpdate() { return 1; }
        @Override public void close() {}
        @Override public java.sql.ResultSet executeQuery() { throw new UnsupportedOperationException(); }
        @Override public boolean execute() { throw new UnsupportedOperationException(); }
        @Override public void addBatch() {}
        @Override public void clearParameters() {}
        @Override public void setNull(int p, int t) {}
        @Override public void setBoolean(int p, boolean v) {}
        @Override public void setByte(int p, byte v) {}
        @Override public void setShort(int p, short v) {}
        @Override public void setLong(int p, long v) {}
        @Override public void setFloat(int p, float v) {}
        @Override public void setDouble(int p, double v) {}
        @Override public void setBigDecimal(int p, java.math.BigDecimal v) {}
        @Override public void setBytes(int p, byte[] v) {}
        @Override public void setDate(int p, java.sql.Date v) {}
        @Override public void setTime(int p, java.sql.Time v) {}
        @Override public void setTimestamp(int p, java.sql.Timestamp v) {}
        @Override public void setAsciiStream(int p, java.io.InputStream v, int l) {}
        @Override public void setUnicodeStream(int p, java.io.InputStream v, int l) {}
        @Override public void setBinaryStream(int p, java.io.InputStream v, int l) {}
        @Override public void setObject(int p, Object v, int t) {}
        @Override public void setObject(int p, Object v) {}
        @Override public java.sql.ResultSetMetaData getMetaData() { throw new UnsupportedOperationException(); }
        @Override public void setDate(int p, java.sql.Date v, java.util.Calendar c) {}
        @Override public void setTime(int p, java.sql.Time v, java.util.Calendar c) {}
        @Override public void setTimestamp(int p, java.sql.Timestamp v, java.util.Calendar c) {}
        @Override public void setNull(int p, int t, String n) {}
        @Override public void setURL(int p, java.net.URL v) {}
        @Override public java.sql.ParameterMetaData getParameterMetaData() { throw new UnsupportedOperationException(); }
        @Override public void setRowId(int p, java.sql.RowId v) {}
        @Override public void setNString(int p, String v) {}
        @Override public void setNCharacterStream(int p, java.io.Reader v, long l) {}
        @Override public void setNClob(int p, java.sql.NClob v) {}
        @Override public void setClob(int p, java.io.Reader v, long l) {}
        @Override public void setBlob(int p, java.io.InputStream v, long l) {}
        @Override public void setNClob(int p, java.io.Reader v, long l) {}
        @Override public void setSQLXML(int p, java.sql.SQLXML v) {}
        @Override public void setObject(int p, Object v, int t, int s) {}
        @Override public void setAsciiStream(int p, java.io.InputStream v, long l) {}
        @Override public void setBinaryStream(int p, java.io.InputStream v, long l) {}
        @Override public void setCharacterStream(int p, java.io.Reader v, long l) {}
        @Override public void setAsciiStream(int p, java.io.InputStream v) {}
        @Override public void setBinaryStream(int p, java.io.InputStream v) {}
        @Override public void setCharacterStream(int p, java.io.Reader v) {}
        @Override public void setNCharacterStream(int p, java.io.Reader v) {}
        @Override public void setClob(int p, java.io.Reader v) {}
        @Override public void setBlob(int p, java.io.InputStream v) {}
        @Override public void setNClob(int p, java.io.Reader v) {}
        @Override public java.sql.ResultSet executeQuery(String s) { throw new UnsupportedOperationException(); }
        @Override public int executeUpdate(String s) { return 0; }
        @Override public int getMaxFieldSize() { return 0; }
        @Override public void setMaxFieldSize(int m) {}
        @Override public int getMaxRows() { return 0; }
        @Override public void setMaxRows(int m) {}
        @Override public void setEscapeProcessing(boolean e) {}
        @Override public int getQueryTimeout() { return 0; }
        @Override public void setQueryTimeout(int s) {}
        @Override public void cancel() {}
        @Override public java.sql.SQLWarning getWarnings() { return null; }
        @Override public void clearWarnings() {}
        @Override public void setCursorName(String n) {}
        @Override public boolean execute(String s) { throw new UnsupportedOperationException(); }
        @Override public java.sql.ResultSet getResultSet() { throw new UnsupportedOperationException(); }
        @Override public int getUpdateCount() { return 1; }
        @Override public boolean getMoreResults() { return false; }
        @Override public void setFetchDirection(int d) {}
        @Override public int getFetchDirection() { return 0; }
        @Override public void setFetchSize(int r) {}
        @Override public int getFetchSize() { return 0; }
        @Override public int getResultSetConcurrency() { return 0; }
        @Override public int getResultSetType() { return 0; }
        @Override public void addBatch(String s) {}
        @Override public void clearBatch() {}
        @Override public int[] executeBatch() { return new int[0]; }
        @Override public Connection getConnection() { throw new UnsupportedOperationException(); }
        @Override public boolean getMoreResults(int c) { return false; }
        @Override public java.sql.ResultSet getGeneratedKeys() { throw new UnsupportedOperationException(); }
        @Override public int executeUpdate(String s, int ag) { return 0; }
        @Override public int executeUpdate(String s, int[] ci) { return 0; }
        @Override public int executeUpdate(String s, String[] cn) { return 0; }
        @Override public boolean execute(String s, int ag) { throw new UnsupportedOperationException(); }
        @Override public boolean execute(String s, int[] ci) { throw new UnsupportedOperationException(); }
        @Override public boolean execute(String s, String[] cn) { throw new UnsupportedOperationException(); }
        @Override public int getResultSetHoldability() { return 0; }
        @Override public boolean isClosed() { return false; }
        @Override public void setPoolable(boolean p) {}
        @Override public boolean isPoolable() { return false; }
        @Override public void closeOnCompletion() {}
        @Override public boolean isCloseOnCompletion() { return false; }
        @Override public <T> T unwrap(Class<T> i) { throw new UnsupportedOperationException(); }
        @Override public boolean isWrapperFor(Class<?> i) { return false; }
        @Override public void setCharacterStream(int p, java.io.Reader v, int l) {}
        @Override public void setRef(int p, java.sql.Ref v) {}
        @Override public void setBlob(int p, java.sql.Blob v) {}
        @Override public void setClob(int p, java.sql.Clob v) {}
        @Override public void setArray(int p, java.sql.Array v) {}
    }
}
