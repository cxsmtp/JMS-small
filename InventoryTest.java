import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.sql.*;
import java.lang.reflect.Field;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Comprehensive test suite for Inventory class SQL injection vulnerability remediation.
 *
 * This test suite validates that:
 * 1. The SQL injection vulnerability has been fixed by using PreparedStatement
 * 2. User input is properly parameterized and not concatenated into SQL queries
 * 3. Malicious SQL injection attempts are blocked
 * 4. Normal functionality continues to work correctly
 */
@RunWith(MockitoJUnitRunner.class)
public class InventoryTest {

    private Inventory inventory;

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private JDesktopPane mockDesktop;

    @Mock
    private ActionEvent mockActionEvent;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        inventory = new Inventory();

        // Setup mock behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Initialize the inventory frame
        inventory.InventoryFrame(mockDesktop);
    }

    @After
    public void tearDown() {
        inventory = null;
    }

    /**
     * Test that PreparedStatement is used instead of Statement for SQL operations.
     * This is the core defense against SQL injection attacks.
     */
    @Test
    public void testUsesPreparedStatementNotStatement() throws Exception {
        // Set up test data with normal input
        setTextFieldValue(inventory, "style_id", "STY001");
        setTextFieldValue(inventory, "Vendor_id", "VEN001");
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", "5");
        setTextFieldValue(inventory, "details", "Test details");

        // Inject mock connection through reflection
        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify that prepareStatement was called (not createStatement)
        verify(mockConnection).prepareStatement(anyString());
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test that SQL injection attempt in style_id field is safely handled.
     * Input: ' OR '1'='1
     * Expected: The malicious input is treated as a literal string value, not SQL code
     */
    @Test
    public void testSQLInjectionInStyleIdIsBlocked() throws Exception {
        String maliciousInput = "' OR '1'='1";

        setTextFieldValue(inventory, "style_id", maliciousInput);
        setTextFieldValue(inventory, "Vendor_id", "VEN001");
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", "5");
        setTextFieldValue(inventory, "details", "Test");

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify that setString was called with the malicious input as a literal string
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection attempt with UNION SELECT attack in vendor_id field.
     * Input: VEN001' UNION SELECT * FROM Users--
     * Expected: Treated as literal string, not executed as SQL
     */
    @Test
    public void testUnionSelectAttackIsBlocked() throws Exception {
        String unionAttack = "VEN001' UNION SELECT * FROM Users--";

        setTextFieldValue(inventory, "style_id", "STY001");
        setTextFieldValue(inventory, "Vendor_id", unionAttack);
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", "5");
        setTextFieldValue(inventory, "details", "Test");

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify the attack string is passed as a parameter, not concatenated
        verify(mockPreparedStatement).setString(2, unionAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection with DROP TABLE command in stone_number field.
     * Input: 5'; DROP TABLE Inventory;--
     * Expected: Treated as literal string value
     */
    @Test
    public void testDropTableAttackIsBlocked() throws Exception {
        String dropTableAttack = "5'; DROP TABLE Inventory;--";

        setTextFieldValue(inventory, "style_id", "STY001");
        setTextFieldValue(inventory, "Vendor_id", "VEN001");
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", dropTableAttack);
        setTextFieldValue(inventory, "details", "Test");

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify the malicious input is parameterized
        verify(mockPreparedStatement).setString(8, dropTableAttack);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that the correct parameterized SQL query structure is used.
     * Expected: Query uses ? placeholders, not string concatenation
     */
    @Test
    public void testParameterizedQueryStructure() throws Exception {
        setTextFieldValue(inventory, "style_id", "STY001");
        setTextFieldValue(inventory, "Vendor_id", "VEN001");
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", "5");
        setTextFieldValue(inventory, "details", "Test");

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify the query uses placeholders
        String expectedQueryPattern = "INSERT INTO Inventory(Style_ID,Vendor_ID,In_Date,Gold,Gold_wt,Stone_Type,Stone_Weight,Stone_numbers,Details) VALUES (?,?,?,?,?,?,?,?,?)";
        verify(mockConnection).prepareStatement(expectedQueryPattern);
    }

    /**
     * Test that all 9 parameters are set correctly in order.
     * This ensures the parameterization is complete and correct.
     */
    @Test
    public void testAllParametersAreSetCorrectly() throws Exception {
        String styleId = "STY123";
        String vendorId = "VEN456";
        String inDate = "12/31/2024";
        String goldCr = "24";
        String goldWt = "15.75";
        String stoneType = "Ruby";
        String stoneWt = "3.2";
        String stoneNumber = "8";
        String details = "Premium quality";

        setTextFieldValue(inventory, "style_id", styleId);
        setTextFieldValue(inventory, "Vendor_id", vendorId);
        setTextFieldValue(inventory, "in_date", inDate);
        setTextFieldValue(inventory, "gold_cr", goldCr);
        setTextFieldValue(inventory, "gold_wt", goldWt);
        setTextFieldValue(inventory, "stone_type", stoneType);
        setTextFieldValue(inventory, "stone_wt", stoneWt);
        setTextFieldValue(inventory, "stone_number", stoneNumber);
        setTextFieldValue(inventory, "details", details);

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify all parameters are set in correct order
        verify(mockPreparedStatement).setString(1, styleId);
        verify(mockPreparedStatement).setString(2, vendorId);
        verify(mockPreparedStatement).setString(3, inDate);
        verify(mockPreparedStatement).setString(4, goldCr);
        verify(mockPreparedStatement).setString(5, goldWt);
        verify(mockPreparedStatement).setString(6, stoneType);
        verify(mockPreparedStatement).setString(7, stoneWt);
        verify(mockPreparedStatement).setString(8, stoneNumber);
        verify(mockPreparedStatement).setString(9, details);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with special characters that could be used in SQL injection.
     * Input: Various SQL metacharacters
     * Expected: All treated as literal strings
     */
    @Test
    public void testSpecialCharactersAreEscaped() throws Exception {
        String specialChars = "'; -- /* */ %";

        setTextFieldValue(inventory, "style_id", specialChars);
        setTextFieldValue(inventory, "Vendor_id", specialChars);
        setTextFieldValue(inventory, "in_date", specialChars);
        setTextFieldValue(inventory, "gold_cr", specialChars);
        setTextFieldValue(inventory, "gold_wt", specialChars);
        setTextFieldValue(inventory, "stone_type", specialChars);
        setTextFieldValue(inventory, "stone_wt", specialChars);
        setTextFieldValue(inventory, "stone_number", specialChars);
        setTextFieldValue(inventory, "details", specialChars);

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify all special characters are parameterized
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(specialChars));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with empty strings to ensure edge cases are handled.
     */
    @Test
    public void testEmptyStringInputs() throws Exception {
        setTextFieldValue(inventory, "style_id", "");
        setTextFieldValue(inventory, "Vendor_id", "");
        setTextFieldValue(inventory, "in_date", "");
        setTextFieldValue(inventory, "gold_cr", "");
        setTextFieldValue(inventory, "gold_wt", "");
        setTextFieldValue(inventory, "stone_type", "");
        setTextFieldValue(inventory, "stone_wt", "");
        setTextFieldValue(inventory, "stone_number", "");
        setTextFieldValue(inventory, "details", "");

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify empty strings are handled correctly
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test with very long input strings that might contain injection attempts.
     */
    @Test
    public void testLongInputStrings() throws Exception {
        StringBuilder longString = new StringBuilder();
        for (int i = 0; i < 100; i++) {
            longString.append("' OR '1'='1' --");
        }
        String longMaliciousInput = longString.toString();

        setTextFieldValue(inventory, "style_id", "STY001");
        setTextFieldValue(inventory, "Vendor_id", "VEN001");
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", "5");
        setTextFieldValue(inventory, "details", longMaliciousInput);

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        // Verify long malicious input is safely parameterized
        verify(mockPreparedStatement).setString(9, longMaliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection with multiple quotes and backslashes.
     * Input: \' \\" \\'
     * Expected: Safely parameterized
     */
    @Test
    public void testQuotesAndBackslashesAreSafe() throws Exception {
        String complexInput = "\\' \\\" \\\\'";

        setTextFieldValue(inventory, "style_id", complexInput);
        setTextFieldValue(inventory, "Vendor_id", "VEN001");
        setTextFieldValue(inventory, "in_date", "01/01/2024");
        setTextFieldValue(inventory, "gold_cr", "18");
        setTextFieldValue(inventory, "gold_wt", "10.5");
        setTextFieldValue(inventory, "stone_type", "Diamond");
        setTextFieldValue(inventory, "stone_wt", "2.5");
        setTextFieldValue(inventory, "stone_number", "5");
        setTextFieldValue(inventory, "details", "Test");

        Field conField = Inventory.class.getDeclaredField("con");
        conField.setAccessible(true);
        conField.set(inventory, mockConnection);

        inventory.actionPerformed(mockActionEvent);

        verify(mockPreparedStatement).setString(1, complexInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Helper method to set text field values using reflection.
     */
    private void setTextFieldValue(Inventory inv, String fieldName, String value) throws Exception {
        Field field = Inventory.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        JTextField textField = (JTextField) field.get(inv);
        textField.setText(value);
    }
}
