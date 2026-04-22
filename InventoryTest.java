import org.junit.Before;
import org.junit.Test;
import org.junit.After;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JDesktopPane;

/**
 * Comprehensive test suite for Inventory class SQL injection remediation.
 *
 * This test suite validates that:
 * 1. The SQL injection vulnerability has been fixed using PreparedStatement
 * 2. Normal input is handled correctly
 * 3. Malicious SQL injection attempts are safely neutralized
 * 4. The application maintains its intended functionality
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;
    private JDesktopPane mockDesktop;

    @Before
    public void setUp() throws Exception {
        inventory = new Inventory();

        // Create mock database objects
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);
        mockDesktop = mock(JDesktopPane.class);

        // Set up the inventory frame
        inventory.InventoryFrame(mockDesktop);
    }

    @After
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
    }

    /**
     * Test Case 1: Verify that legitimate data is processed correctly
     * This ensures the fix maintains normal functionality
     */
    @Test
    public void testLegitimateDataInsertion() throws Exception {
        // Arrange: Set up legitimate test data
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Beautiful ring with diamonds");

        // Mock the database connection and prepared statement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Replace the actual connection with mock
        inventory.con = mockConnection;

        // Act: Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Verify PreparedStatement was used (not Statement)
        verify(mockConnection).prepareStatement(anyString());
        verify(mockPreparedStatement).setString(eq(1), eq("STYLE001"));
        verify(mockPreparedStatement).setString(eq(2), eq("VENDOR123"));
        verify(mockPreparedStatement).setString(eq(3), eq("01/04/2026"));
        verify(mockPreparedStatement).setString(eq(4), eq("18K"));
        verify(mockPreparedStatement).setString(eq(5), eq("5.5"));
        verify(mockPreparedStatement).setString(eq(6), eq("Diamond"));
        verify(mockPreparedStatement).setString(eq(7), eq("1.2"));
        verify(mockPreparedStatement).setString(eq(8), eq("3"));
        verify(mockPreparedStatement).setString(eq(9), eq("Beautiful ring with diamonds"));
        verify(mockPreparedStatement).executeUpdate();
        verify(mockPreparedStatement).close();
    }

    /**
     * Test Case 2: SQL Injection Attack - Single Quote Injection
     * Tests that single quotes in input are properly escaped and neutralized
     */
    @Test
    public void testSQLInjectionWithSingleQuote() throws Exception {
        // Arrange: Malicious input with single quote to break out of SQL string
        String maliciousInput = "STYLE001'); DROP TABLE Inventory; --";
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Normal details");

        // Mock the database connection
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Verify that PreparedStatement treats the malicious input as a literal string
        // The malicious SQL should be passed as parameter, not executed
        verify(mockPreparedStatement).setString(eq(1), eq(maliciousInput));
        verify(mockPreparedStatement).executeUpdate();

        // Verify that executeUpdate was NOT called on Statement (vulnerable approach)
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test Case 3: SQL Injection Attack - UNION-based Attack
     * Tests protection against UNION-based SQL injection
     */
    @Test
    public void testSQLInjectionUnionAttack() throws Exception {
        // Arrange: UNION-based injection attempt
        String unionAttack = "STYLE001' UNION SELECT * FROM Users WHERE '1'='1";
        inventory.style_id.setText(unionAttack);
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Normal details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: The UNION attack is treated as literal string data
        verify(mockPreparedStatement).setString(eq(1), eq(unionAttack));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 4: SQL Injection Attack - Boolean-based Blind Injection
     * Tests protection against boolean-based blind SQL injection
     */
    @Test
    public void testSQLInjectionBooleanBlind() throws Exception {
        // Arrange: Boolean-based blind injection
        String blindInjection = "VENDOR123' OR '1'='1";
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText(blindInjection);
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Normal details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Verify the malicious condition is treated as data
        verify(mockPreparedStatement).setString(eq(2), eq(blindInjection));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 5: SQL Injection Attack - Comment-based Injection
     * Tests protection against SQL comment injection (-- and /* )
     */
    @Test
    public void testSQLInjectionWithComments() throws Exception {
        // Arrange: Comment-based injection to bypass remaining query
        String commentInjection = "STYLE001' OR 1=1 --";
        inventory.style_id.setText(commentInjection);
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Normal details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Comment characters are treated as literal data
        verify(mockPreparedStatement).setString(eq(1), eq(commentInjection));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 6: Multiple Fields with SQL Injection Attempts
     * Tests that all fields are properly parameterized
     */
    @Test
    public void testMultipleFieldsSQLInjection() throws Exception {
        // Arrange: Inject malicious data into multiple fields
        inventory.style_id.setText("STYLE'; DELETE FROM Inventory; --");
        inventory.Vendor_id.setText("VEN' OR '1'='1");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K' UNION SELECT password FROM users --");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3' OR 1=1 --");
        inventory.details.setText("Details'; DROP TABLE Users; --");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: All malicious inputs are treated as literal strings
        verify(mockPreparedStatement).setString(eq(1), contains("DELETE"));
        verify(mockPreparedStatement).setString(eq(2), contains("OR"));
        verify(mockPreparedStatement).setString(eq(4), contains("UNION"));
        verify(mockPreparedStatement).setString(eq(8), contains("OR 1=1"));
        verify(mockPreparedStatement).setString(eq(9), contains("DROP TABLE"));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 7: Special Characters in Legitimate Data
     * Ensures that legitimate data with special characters works correctly
     */
    @Test
    public void testSpecialCharactersInLegitimateData() throws Exception {
        // Arrange: Legitimate data that contains special SQL characters
        inventory.style_id.setText("STYLE-001");
        inventory.Vendor_id.setText("O'Brien & Sons");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Client's preference: 'vintage style'");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Special characters are safely handled
        verify(mockPreparedStatement).setString(eq(2), eq("O'Brien & Sons"));
        verify(mockPreparedStatement).setString(eq(9), eq("Client's preference: 'vintage style'"));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 8: Empty and Null Values
     * Tests handling of edge cases with empty or null inputs
     */
    @Test
    public void testEmptyAndNullValues() throws Exception {
        // Arrange: Mix of empty and null values
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("");
        inventory.stone_wt.setText("");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Empty strings are handled safely
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 9: Verify PreparedStatement Query Structure
     * Ensures the SQL query uses proper parameterized structure
     */
    @Test
    public void testPreparedStatementQueryStructure() throws Exception {
        // Arrange
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Verify the query contains placeholders (?) not concatenated values
        verify(mockConnection).prepareStatement(
            eq("INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)")
        );

        // Verify that the old vulnerable pattern is NOT used
        verify(mockConnection, never()).prepareStatement(contains("'"+"+"));
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test Case 10: Time-based SQL Injection Attack
     * Tests protection against time-based blind SQL injection
     */
    @Test
    public void testTimeBasedSQLInjection() throws Exception {
        // Arrange: Time-based injection attempt using WAITFOR DELAY or SLEEP
        String timeBasedInjection = "STYLE001'; WAITFOR DELAY '00:00:10'--";
        inventory.style_id.setText(timeBasedInjection);
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Normal details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Time-based attack is neutralized
        verify(mockPreparedStatement).setString(eq(1), eq(timeBasedInjection));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test Case 11: Stacked Queries SQL Injection
     * Tests protection against stacked query injection
     */
    @Test
    public void testStackedQueriesSQLInjection() throws Exception {
        // Arrange: Attempt to execute multiple statements
        String stackedQueries = "STYLE001'; INSERT INTO Admin (username, password) VALUES ('hacker', 'pass'); --";
        inventory.style_id.setText(stackedQueries);
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Normal details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: Stacked queries are treated as literal string
        verify(mockPreparedStatement).setString(eq(1), eq(stackedQueries));
        verify(mockPreparedStatement).executeUpdate();
        verify(mockPreparedStatement).close();
    }

    /**
     * Test Case 12: Resource Cleanup
     * Verifies that PreparedStatement is properly closed after execution
     */
    @Test
    public void testResourceCleanup() throws Exception {
        // Arrange
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR123");
        inventory.in_date.setText("01/04/2026");
        inventory.gold_cr.setText("18K");
        inventory.gold_wt.setText("5.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("1.2");
        inventory.stone_number.setText("3");
        inventory.details.setText("Details");

        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
        inventory.con = mockConnection;

        // Act
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Assert: PreparedStatement is properly closed
        verify(mockPreparedStatement).close();
    }
}
