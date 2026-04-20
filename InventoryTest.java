import org.junit.Before;
import org.junit.Test;
import org.junit.After;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;

import java.sql.*;
import javax.swing.*;
import java.awt.event.ActionEvent;

/**
 * Comprehensive test suite for Inventory class focusing on SQL injection prevention.
 *
 * This test class validates:
 * 1. SQL injection vulnerability is fixed (uses PreparedStatement)
 * 2. Parameterized queries properly escape malicious input
 * 3. Normal functionality continues to work correctly
 * 4. Attack vectors are blocked effectively
 */
public class InventoryTest {

    private Inventory inventory;
    private Connection mockConnection;
    private PreparedStatement mockPreparedStatement;
    private Statement mockStatement;

    @Before
    public void setUp() throws SQLException {
        inventory = new Inventory();

        // Mock JDBC components to test SQL injection protection
        mockConnection = mock(Connection.class);
        mockPreparedStatement = mock(PreparedStatement.class);
        mockStatement = mock(Statement.class);

        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockConnection.createStatement()).thenReturn(mockStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Inject mocks into inventory instance
        inventory.con = mockConnection;
    }

    @After
    public void tearDown() {
        inventory = null;
        mockConnection = null;
        mockPreparedStatement = null;
        mockStatement = null;
    }

    /**
     * Test 1: Verify that PreparedStatement is used instead of Statement
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testUsesPreparedStatementNotStatement() throws SQLException {
        // Setup text field inputs with normal data
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Beautiful ring");

        // Trigger the action
        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify PreparedStatement was used with parameterized query
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );

        // Verify parameters were set correctly (9 parameters total)
        verify(mockPreparedStatement).setString(1, "STY001");
        verify(mockPreparedStatement).setString(2, "VEN001");
        verify(mockPreparedStatement).setString(3, "01/01/2024");
        verify(mockPreparedStatement).setString(4, "18");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "Diamond");
        verify(mockPreparedStatement).setString(7, "2.5");
        verify(mockPreparedStatement).setString(8, "5");
        verify(mockPreparedStatement).setString(9, "Beautiful ring");

        // Verify executeUpdate was called on PreparedStatement
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 2: Verify SQL injection attack with single quote is neutralized
     * Attack vector: ' OR '1'='1
     */
    @Test
    public void testBlocksSQLInjectionWithSingleQuotes() throws SQLException {
        // Setup malicious input attempting SQL injection
        String maliciousStyleId = "STY001' OR '1'='1";
        inventory.style_id.setText(maliciousStyleId);
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is passed as a parameter (safely escaped)
        // The PreparedStatement will treat the entire string as data, not SQL code
        verify(mockPreparedStatement).setString(1, maliciousStyleId);
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement.executeUpdate is NOT called (vulnerable method)
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 3: Verify SQL injection with comment injection is blocked
     * Attack vector: '; DROP TABLE Inventory; --
     */
    @Test
    public void testBlocksSQLInjectionWithDropTable() throws SQLException {
        // Setup malicious input attempting to drop the table
        String maliciousVendorId = "VEN001'; DROP TABLE Inventory; --";
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText(maliciousVendorId);
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(2, maliciousVendorId);
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement is not used
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 4: Verify SQL injection with UNION attack is blocked
     * Attack vector: ' UNION SELECT * FROM Users --
     */
    @Test
    public void testBlocksSQLInjectionWithUnion() throws SQLException {
        // Setup malicious input attempting UNION-based SQL injection
        String maliciousDetails = "Test' UNION SELECT username,password,email,NULL,NULL,NULL,NULL,NULL,NULL FROM Users --";
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(maliciousDetails);

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(9, maliciousDetails);
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement is not used
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 5: Verify SQL injection with multiple quotes and semicolons is blocked
     * Complex attack vector with multiple SQL commands
     */
    @Test
    public void testBlocksComplexSQLInjection() throws SQLException {
        // Setup complex malicious input
        String maliciousStoneType = "'; UPDATE Inventory SET Gold_wt='0' WHERE '1'='1'; --";
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText(maliciousStoneType);
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(6, maliciousStoneType);
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement is not used
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 6: Verify normal inputs with special characters work correctly
     * Tests legitimate use cases with apostrophes in names
     */
    @Test
    public void testHandlesLegitimateSpecialCharacters() throws SQLException {
        // Setup inputs with legitimate special characters
        inventory.style_id.setText("O'Reilly-Design");
        inventory.Vendor_id.setText("Vendor's Choice Ltd.");
        inventory.in_date.setText("12/25/2024");
        inventory.gold_cr.setText("22");
        inventory.gold_wt.setText("15.75");
        inventory.stone_type.setText("Ruby & Sapphire");
        inventory.stone_wt.setText("3.25");
        inventory.stone_number.setText("8");
        inventory.details.setText("Customer's special order - 50% deposit paid");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all parameters are set correctly including special characters
        verify(mockPreparedStatement).setString(1, "O'Reilly-Design");
        verify(mockPreparedStatement).setString(2, "Vendor's Choice Ltd.");
        verify(mockPreparedStatement).setString(3, "12/25/2024");
        verify(mockPreparedStatement).setString(4, "22");
        verify(mockPreparedStatement).setString(5, "15.75");
        verify(mockPreparedStatement).setString(6, "Ruby & Sapphire");
        verify(mockPreparedStatement).setString(7, "3.25");
        verify(mockPreparedStatement).setString(8, "8");
        verify(mockPreparedStatement).setString(9, "Customer's special order - 50% deposit paid");

        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 7: Verify empty strings are handled correctly
     */
    @Test
    public void testHandlesEmptyInputs() throws SQLException {
        // Setup with some empty inputs
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify empty strings are passed as parameters
        verify(mockPreparedStatement).setString(1, "");
        verify(mockPreparedStatement).setString(3, "");
        verify(mockPreparedStatement).setString(5, "");
        verify(mockPreparedStatement).setString(8, "");
        verify(mockPreparedStatement).setString(9, "");

        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 8: Verify SQL injection with encoded characters is blocked
     * Tests URL-encoded and hex-encoded attack vectors
     */
    @Test
    public void testBlocksEncodedSQLInjection() throws SQLException {
        // Setup malicious input with encoded characters
        String maliciousInput = "%27%20OR%20%271%27%3D%271"; // URL-encoded ' OR '1'='1
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the encoded input is treated as data, not code
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement is not used
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 9: Verify SQL injection with stacked queries is blocked
     * Attack vector: '; INSERT INTO Admin VALUES ('hacker','password'); --
     */
    @Test
    public void testBlocksStackedQueryInjection() throws SQLException {
        // Setup malicious input attempting stacked queries
        String maliciousGoldCarat = "18'; INSERT INTO Admin VALUES ('hacker','password'); --";
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText(maliciousGoldCarat);
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(4, maliciousGoldCarat);
        verify(mockPreparedStatement).executeUpdate();

        // Verify Statement is not used
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 10: Verify that all 9 parameters are always set
     * Regression test to ensure no parameters are missed
     */
    @Test
    public void testAllParametersAreSet() throws SQLException {
        // Setup all inputs
        inventory.style_id.setText("STY123");
        inventory.Vendor_id.setText("VEN456");
        inventory.in_date.setText("06/15/2024");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("20.0");
        inventory.stone_type.setText("Emerald");
        inventory.stone_wt.setText("5.0");
        inventory.stone_number.setText("10");
        inventory.details.setText("Premium quality");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify all 9 parameters are set exactly once
        verify(mockPreparedStatement, times(1)).setString(eq(1), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(2), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(3), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(4), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(5), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(6), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(7), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(8), anyString());
        verify(mockPreparedStatement, times(1)).setString(eq(9), anyString());

        // Verify executeUpdate is called
        verify(mockPreparedStatement, times(1)).executeUpdate();
    }

    /**
     * Test 11: Verify SQL injection with boolean-based blind injection is blocked
     * Attack vector: ' AND '1'='2
     */
    @Test
    public void testBlocksBooleanBasedBlindSQLInjection() throws SQLException {
        // Setup malicious input for boolean-based blind SQL injection
        String maliciousInput = "STY001' AND '1'='2";
        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("VEN001");
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Verify the vulnerable Statement.executeUpdate is never called
        verify(mockStatement, never()).executeUpdate(anyString());
    }

    /**
     * Test 12: Verify SQL injection with time-based blind injection is blocked
     * Attack vector: '; WAITFOR DELAY '00:00:05'; --
     */
    @Test
    public void testBlocksTimeBasedBlindSQLInjection() throws SQLException {
        // Setup malicious input for time-based blind SQL injection
        String maliciousInput = "VEN001'; WAITFOR DELAY '00:00:05'; --";
        inventory.style_id.setText("STY001");
        inventory.Vendor_id.setText(maliciousInput);
        inventory.in_date.setText("01/01/2024");
        inventory.gold_cr.setText("18");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test");

        ActionEvent mockEvent = mock(ActionEvent.class);
        inventory.actionPerformed(mockEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(2, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();

        // Verify the vulnerable Statement.executeUpdate is never called
        verify(mockStatement, never()).executeUpdate(anyString());
    }
}
