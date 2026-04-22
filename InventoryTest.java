import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.junit.MockitoJUnitRunner;
import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

import java.sql.*;
import java.awt.event.ActionEvent;
import javax.swing.JTextField;

/**
 * Test suite for Inventory class to validate SQL injection vulnerability remediation.
 *
 * This test suite verifies:
 * 1. PreparedStatement is used instead of Statement with string concatenation
 * 2. User inputs are properly parameterized to prevent SQL injection
 * 3. SQL injection attack payloads are safely handled
 * 4. Normal functionality remains intact
 */
@RunWith(MockitoJUnitRunner.class)
public class InventoryTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Spy
    private Inventory inventory;

    private JTextField styleIdField;
    private JTextField vendorIdField;
    private JTextField inDateField;
    private JTextField goldCrField;
    private JTextField goldWtField;
    private JTextField stoneTypeField;
    private JTextField stoneWtField;
    private JTextField stoneNumberField;
    private JTextField detailsField;

    @Before
    public void setUp() throws Exception {
        // Initialize text fields through reflection to test the actionPerformed method
        styleIdField = new JTextField();
        vendorIdField = new JTextField();
        inDateField = new JTextField();
        goldCrField = new JTextField();
        goldWtField = new JTextField();
        stoneTypeField = new JTextField();
        stoneWtField = new JTextField();
        stoneNumberField = new JTextField();
        detailsField = new JTextField();

        // Set fields on inventory object via reflection
        java.lang.reflect.Field styleId = Inventory.class.getDeclaredField("style_id");
        styleId.setAccessible(true);
        styleId.set(inventory, styleIdField);

        java.lang.reflect.Field vendorId = Inventory.class.getDeclaredField("Vendor_id");
        vendorId.setAccessible(true);
        vendorId.set(inventory, vendorIdField);

        java.lang.reflect.Field inDate = Inventory.class.getDeclaredField("in_date");
        inDate.setAccessible(true);
        inDate.set(inventory, inDateField);

        java.lang.reflect.Field goldCr = Inventory.class.getDeclaredField("gold_cr");
        goldCr.setAccessible(true);
        goldCr.set(inventory, goldCrField);

        java.lang.reflect.Field goldWt = Inventory.class.getDeclaredField("gold_wt");
        goldWt.setAccessible(true);
        goldWt.set(inventory, goldWtField);

        java.lang.reflect.Field stoneType = Inventory.class.getDeclaredField("stone_type");
        stoneType.setAccessible(true);
        stoneType.set(inventory, stoneTypeField);

        java.lang.reflect.Field stoneWt = Inventory.class.getDeclaredField("stone_wt");
        stoneWt.setAccessible(true);
        stoneWt.set(inventory, stoneWtField);

        java.lang.reflect.Field stoneNumber = Inventory.class.getDeclaredField("stone_number");
        stoneNumber.setAccessible(true);
        stoneNumber.set(inventory, stoneNumberField);

        java.lang.reflect.Field details = Inventory.class.getDeclaredField("details");
        details.setAccessible(true);
        details.set(inventory, detailsField);

        // Mock static DriverManager.getConnection
        MockedStatic<DriverManager> driverManagerMock = mockStatic(DriverManager.class);
        driverManagerMock.when(() -> DriverManager.getConnection(anyString()))
                        .thenReturn(mockConnection);

        // Setup mock connection to return mock prepared statement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    /**
     * Test that PreparedStatement is used with parameterized query
     * This is the core fix for SQL injection vulnerability
     */
    @Test
    public void testUsesPreparedStatementWithParameterizedQuery() throws Exception {
        // Arrange
        styleIdField.setText("STYLE001");
        vendorIdField.setText("VENDOR001");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText("Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - Verify PreparedStatement is created with parameterized query (using ? placeholders)
        String expectedQuery = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        verify(mockConnection).prepareStatement(expectedQuery);

        // Verify all parameters are set via setString (not concatenated)
        verify(mockPreparedStatement).setString(1, "STYLE001");
        verify(mockPreparedStatement).setString(2, "VENDOR001");
        verify(mockPreparedStatement).setString(3, "01/01/2024");
        verify(mockPreparedStatement).setString(4, "18");
        verify(mockPreparedStatement).setString(5, "10.5");
        verify(mockPreparedStatement).setString(6, "Diamond");
        verify(mockPreparedStatement).setString(7, "2.5");
        verify(mockPreparedStatement).setString(8, "5");
        verify(mockPreparedStatement).setString(9, "Test details");

        // Verify executeUpdate is called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection attack via single quote in style_id field
     * With PreparedStatement, this should be safely handled as a parameter value
     */
    @Test
    public void testSqlInjectionAttemptWithSingleQuoteInStyleId() throws Exception {
        // Arrange - SQL injection payload
        String sqlInjectionPayload = "STYLE001' OR '1'='1";
        styleIdField.setText(sqlInjectionPayload);
        vendorIdField.setText("VENDOR001");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText("Normal details");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - The malicious input should be treated as a literal string parameter
        // NOT as SQL code that could bypass authentication or modify the query
        verify(mockPreparedStatement).setString(1, sqlInjectionPayload);

        // Verify the parameterized query is used (not concatenated)
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );
    }

    /**
     * Test SQL injection attack via comment injection in vendor_id field
     */
    @Test
    public void testSqlInjectionAttemptWithCommentInjection() throws Exception {
        // Arrange - SQL injection with comment to bypass rest of query
        String sqlInjectionPayload = "VENDOR001'); DROP TABLE Inventory;--";
        styleIdField.setText("STYLE001");
        vendorIdField.setText(sqlInjectionPayload);
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText("Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - The injection payload should be safely parameterized
        verify(mockPreparedStatement).setString(2, sqlInjectionPayload);
        verify(mockPreparedStatement).executeUpdate();

        // Verify no Statement.executeUpdate(String) is called (vulnerable method)
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test SQL injection attack via UNION-based injection in details field
     */
    @Test
    public void testSqlInjectionAttemptWithUnionInjection() throws Exception {
        // Arrange - UNION-based SQL injection
        String sqlInjectionPayload = "Details') UNION SELECT * FROM Users WHERE '1'='1";
        styleIdField.setText("STYLE001");
        vendorIdField.setText("VENDOR001");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText(sqlInjectionPayload);

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - The UNION injection should be treated as literal text
        verify(mockPreparedStatement).setString(9, sqlInjectionPayload);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with special characters that could cause SQL syntax errors
     * if not properly parameterized
     */
    @Test
    public void testSpecialCharactersAreProperlyHandled() throws Exception {
        // Arrange - Various special characters
        styleIdField.setText("STYLE'001");
        vendorIdField.setText("VENDOR\"002");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18;DELETE");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond\\Stone");
        stoneWtField.setText("2.5`");
        stoneNumberField.setText("5%");
        detailsField.setText("Test; DROP TABLE--");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - All special characters should be safely handled as parameters
        verify(mockPreparedStatement).setString(1, "STYLE'001");
        verify(mockPreparedStatement).setString(2, "VENDOR\"002");
        verify(mockPreparedStatement).setString(4, "18;DELETE");
        verify(mockPreparedStatement).setString(6, "Diamond\\Stone");
        verify(mockPreparedStatement).setString(7, "2.5`");
        verify(mockPreparedStatement).setString(8, "5%");
        verify(mockPreparedStatement).setString(9, "Test; DROP TABLE--");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with empty strings to ensure no SQL syntax errors
     */
    @Test
    public void testEmptyInputsAreHandledCorrectly() throws Exception {
        // Arrange
        styleIdField.setText("");
        vendorIdField.setText("");
        inDateField.setText("");
        goldCrField.setText("");
        goldWtField.setText("");
        stoneTypeField.setText("");
        stoneWtField.setText("");
        stoneNumberField.setText("");
        detailsField.setText("");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - Empty strings should be handled as valid parameter values
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with null-like strings (the string "null" vs actual null)
     */
    @Test
    public void testNullStringInputsAreHandledCorrectly() throws Exception {
        // Arrange
        styleIdField.setText("null");
        vendorIdField.setText("NULL");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText("null");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - The string "null" should be treated as a literal string
        verify(mockPreparedStatement).setString(1, "null");
        verify(mockPreparedStatement).setString(2, "NULL");
        verify(mockPreparedStatement).setString(9, "null");
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test resource cleanup - PreparedStatement and Connection should be closed
     */
    @Test
    public void testResourcesAreProperlyClosedAfterExecution() throws Exception {
        // Arrange
        styleIdField.setText("STYLE001");
        vendorIdField.setText("VENDOR001");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText("Test details");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - Resources should be closed in finally block
        verify(mockPreparedStatement).close();
        verify(mockConnection).close();
    }

    /**
     * Test resource cleanup even when exception occurs
     */
    @Test
    public void testResourcesAreClosedEvenOnException() throws Exception {
        // Arrange
        styleIdField.setText("STYLE001");
        vendorIdField.setText("VENDOR001");
        inDateField.setText("01/01/2024");
        goldCrField.setText("18");
        goldWtField.setText("10.5");
        stoneTypeField.setText("Diamond");
        stoneWtField.setText("2.5");
        stoneNumberField.setText("5");
        detailsField.setText("Test details");

        // Simulate exception during execution
        when(mockPreparedStatement.executeUpdate()).thenThrow(new SQLException("Test exception"));

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        try {
            inventory.actionPerformed(mockEvent);
        } catch (Exception e) {
            // Expected
        }

        // Assert - Resources should still be closed despite exception
        verify(mockPreparedStatement).close();
        verify(mockConnection).close();
    }

    /**
     * Integration-style test verifying the complete flow
     */
    @Test
    public void testCompleteFlowWithValidData() throws Exception {
        // Arrange
        styleIdField.setText("GOLD-RING-001");
        vendorIdField.setText("TIFFANY-NY");
        inDateField.setText("15/04/2024");
        goldCrField.setText("22");
        goldWtField.setText("15.75");
        stoneTypeField.setText("Emerald");
        stoneWtField.setText("3.25");
        stoneNumberField.setText("7");
        detailsField.setText("Beautiful emerald ring with 22 carat gold");

        ActionEvent mockEvent = mock(ActionEvent.class);

        // Act
        inventory.actionPerformed(mockEvent);

        // Assert - Verify complete parameterized flow
        verify(mockConnection).prepareStatement(
            "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)"
        );
        verify(mockPreparedStatement).setString(1, "GOLD-RING-001");
        verify(mockPreparedStatement).setString(2, "TIFFANY-NY");
        verify(mockPreparedStatement).setString(3, "15/04/2024");
        verify(mockPreparedStatement).setString(4, "22");
        verify(mockPreparedStatement).setString(5, "15.75");
        verify(mockPreparedStatement).setString(6, "Emerald");
        verify(mockPreparedStatement).setString(7, "3.25");
        verify(mockPreparedStatement).setString(8, "7");
        verify(mockPreparedStatement).setString(9, "Beautiful emerald ring with 22 carat gold");
        verify(mockPreparedStatement).executeUpdate();
        verify(mockPreparedStatement).close();
        verify(mockConnection).close();
    }
}
