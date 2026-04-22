import org.junit.Test;
import org.junit.Before;
import org.junit.After;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.lang.reflect.Field;

/**
 * Comprehensive test suite for Inventory class to validate SQL injection remediation.
 *
 * These tests verify that:
 * 1. The SQL query uses PreparedStatement with parameterized queries
 * 2. User input is safely bound to parameters and cannot inject SQL
 * 3. The functionality remains correct after the security fix
 * 4. Various injection attack vectors are properly prevented
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private JDesktopPane mockDesktop;

    @Before
    public void setUp() throws Exception {
        inventory = new Inventory();
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockDesktop = mock(JDesktopPane.class);

        // Set up the inventory frame
        inventory.InventoryFrame(mockDesktop);

        // Mock the connection and prepared statement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Inject the mock connection using reflection
        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        Field pstmtField = Inventory.class.getDeclaredField("pstmt");
        pstmtField.setAccessible(true);
        pstmtField.set(inventory, mockPreparedStatement);
    }

    @After
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
    }

    /**
     * Test that the SQL query uses parameterized queries (PreparedStatement).
     * This is the core security fix - parameterized queries prevent SQL injection.
     */
    @Test
    public void testUsesParameterizedQuery() throws Exception {
        // Arrange - Set normal input values
        setInventoryFields("ST001", "V001", "2024-01-15", "18", "10.5",
                          "Diamond", "2.5", "5", "Test item");

        // Mock the DriverManager and Class.forName behavior
        mockStaticDatabaseSetup();

        // Act - Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Verify PreparedStatement was used with parameterized query
        verify(mockConnection).prepareStatement(
            eq("INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)")
        );

        // Verify all parameters were set using setString (safe parameterization)
        verify(mockPreparedStatement).setString(1, "ST001");
        verify(mockPreparedStatement).setString(2, "V001");
        verify(mockPreparedStatement).setString(3, "2024-01-15");
        verify(mockPreparedStatement).setString(4, "18");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "Diamond");
        verify(mockPreparedStatement).setString(7, "2.5");
        verify(mockPreparedStatement).setString(8, "5");
        verify(mockPreparedStatement).setString(9, "Test item");

        // Verify executeUpdate was called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection attempt via stone_type field.
     * Attempts a classic SQL injection attack: ' OR '1'='1
     * The parameterized query should treat this as literal string data.
     */
    @Test
    public void testSQLInjectionAttemptInStoneType() throws Exception {
        // Arrange - Set malicious input attempting SQL injection
        String maliciousInput = "' OR '1'='1";
        setInventoryFields("ST001", "V001", "2024-01-15", "18", "10.5",
                          maliciousInput, "2.5", "5", "Test");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - The malicious input should be passed as a safe parameter
        // PreparedStatement will escape it properly, preventing SQL injection
        verify(mockPreparedStatement).setString(6, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Verify no concatenated query was used
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test SQL injection attempt via style_id field.
     * Attempts to inject additional SQL commands: ST001'; DROP TABLE Inventory--
     */
    @Test
    public void testSQLInjectionAttemptWithDropTable() throws Exception {
        // Arrange - Attempt to drop a table via injection
        String maliciousInput = "ST001'; DROP TABLE Inventory--";
        setInventoryFields(maliciousInput, "V001", "2024-01-15", "18", "10.5",
                          "Diamond", "2.5", "5", "Test");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - The malicious input is safely parameterized
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // The PreparedStatement ensures this is treated as data, not SQL code
    }

    /**
     * Test SQL injection attempt via details field with UNION attack.
     * Attempts: '); SELECT * FROM Users WHERE '1'='1
     */
    @Test
    public void testSQLInjectionAttemptWithUnion() throws Exception {
        // Arrange - Attempt UNION-based SQL injection
        String maliciousInput = "'); SELECT * FROM Users WHERE '1'='1";
        setInventoryFields("ST001", "V001", "2024-01-15", "18", "10.5",
                          "Diamond", "2.5", "5", maliciousInput);

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Malicious SQL is neutralized by parameterization
        verify(mockPreparedStatement).setString(9, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with special characters that might cause issues in concatenated SQL.
     * Includes single quotes, double quotes, backslashes, etc.
     */
    @Test
    public void testSpecialCharactersHandling() throws Exception {
        // Arrange - Input with various special characters
        setInventoryFields("ST'001", "V\"001", "2024-01-15", "18\\n", "10.5",
                          "Di'a\"mond\\", "2.5", "5;--", "Test\nItem");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - All special characters are safely handled
        verify(mockPreparedStatement).setString(1, "ST'001");
        verify(mockPreparedStatement).setString(2, "V\"001");
        verify(mockPreparedStatement).setString(3, "2024-01-15");
        verify(mockPreparedStatement).setString(4, "18\\n");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "Di'a\"mond\\");
        verify(mockPreparedStatement).setString(7, "2.5");
        verify(mockPreparedStatement).setString(8, "5;--");
        verify(mockPreparedStatement).setString(9, "Test\nItem");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with NULL or empty inputs to ensure robustness.
     */
    @Test
    public void testEmptyInputsHandling() throws Exception {
        // Arrange - Empty inputs
        setInventoryFields("", "", "", "", "", "", "", "", "");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Empty strings are safely handled
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with maximum length inputs to verify no truncation attacks.
     */
    @Test
    public void testMaximumLengthInputs() throws Exception {
        // Arrange - Very long inputs that might overflow buffers in vulnerable code
        String longString = generateLongString(1000);
        setInventoryFields(longString, longString, "2024-01-15", "18", "10.5",
                          longString, "2.5", "5", longString);

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Long inputs are safely parameterized
        verify(mockPreparedStatement).setString(1, longString);
        verify(mockPreparedStatement).setString(2, longString);
        verify(mockPreparedStatement).setString(6, longString);
        verify(mockPreparedStatement).setString(9, longString);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL comment injection attempts.
     * Attempts to use SQL comments to bypass logic: -- or /* */
     */
    @Test
    public void testSQLCommentInjectionAttempts() throws Exception {
        // Arrange - Various SQL comment styles
        setInventoryFields("ST001--", "V001/*", "2024-01-15*/", "18", "10.5",
                          "Diamond--comment", "2.5", "5/*test*/", "Detail--");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - SQL comments are treated as literal data
        verify(mockPreparedStatement).setString(1, "ST001--");
        verify(mockPreparedStatement).setString(2, "V001/*");
        verify(mockPreparedStatement).setString(3, "2024-01-15*/");
        verify(mockPreparedStatement).setString(6, "Diamond--comment");
        verify(mockPreparedStatement).setString(8, "5/*test*/");
        verify(mockPreparedStatement).setString(9, "Detail--");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test blind SQL injection attempts with time-based payloads.
     * Example: '; WAITFOR DELAY '00:00:05'--
     */
    @Test
    public void testBlindSQLInjectionAttempts() throws Exception {
        // Arrange - Time-based blind SQL injection attempt
        String timeBasedPayload = "'; WAITFOR DELAY '00:00:05'--";
        setInventoryFields("ST001", "V001", "2024-01-15", "18", "10.5",
                          timeBasedPayload, "2.5", "5", "Test");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Time-based payload is neutralized
        verify(mockPreparedStatement).setString(6, timeBasedPayload);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test stacked queries injection attempt.
     * Attempts: '; DELETE FROM Inventory; --
     */
    @Test
    public void testStackedQueriesInjection() throws Exception {
        // Arrange - Stacked queries attack
        String stackedQuery = "'; DELETE FROM Inventory; --";
        setInventoryFields("ST001", "V001", "2024-01-15", "18", "10.5",
                          stackedQuery, "2.5", "5", "Test");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Stacked queries are prevented by parameterization
        verify(mockPreparedStatement).setString(6, stackedQuery);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test legitimate data with apostrophes (O'Brien, etc.).
     * This verifies functionality is preserved after the fix.
     */
    @Test
    public void testLegitimateApostrophesInData() throws Exception {
        // Arrange - Legitimate data containing apostrophes
        setInventoryFields("ST001", "O'Brien Jewelry", "2024-01-15", "18", "10.5",
                          "Queen's Diamond", "2.5", "5", "Customer's special order");

        mockStaticDatabaseSetup();

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert - Apostrophes are correctly handled without breaking functionality
        verify(mockPreparedStatement).setString(2, "O'Brien Jewelry");
        verify(mockPreparedStatement).setString(6, "Queen's Diamond");
        verify(mockPreparedStatement).setString(9, "Customer's special order");
        verify(mockPreparedStatement).executeUpdate();
    }

    // Helper methods

    /**
     * Helper method to set all inventory fields via reflection.
     */
    private void setInventoryFields(String styleId, String vendorId, String inDate,
                                    String goldCr, String goldWt, String stoneType,
                                    String stoneWt, String stoneNumber, String details)
            throws Exception {
        setTextField("style_id", styleId);
        setTextField("Vendor_id", vendorId);
        setTextField("in_date", inDate);
        setTextField("gold_cr", goldCr);
        setTextField("gold_wt", goldWt);
        setTextField("stone_type", stoneType);
        setTextField("stone_wt", stoneWt);
        setTextField("stone_number", stoneNumber);
        setTextField("details", details);
    }

    /**
     * Helper method to set a text field value using reflection.
     */
    private void setTextField(String fieldName, String value) throws Exception {
        Field field = Inventory.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(inventory);
        textField.setText(value);
    }

    /**
     * Helper method to generate a long string for testing.
     */
    private String generateLongString(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append((char) ('A' + (i % 26)));
        }
        return sb.toString();
    }

    /**
     * Mock the static database setup methods.
     * In a real test environment, you would use PowerMock or similar for this.
     */
    private void mockStaticDatabaseSetup() throws Exception {
        // This is a placeholder for mocking Class.forName and DriverManager
        // In practice, dependency injection would make this cleaner
        // For this test, we're directly injecting the mock connection
    }
}
