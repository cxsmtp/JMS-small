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
 * Test suite for Inventory class to verify SQL injection vulnerability remediation.
 *
 * This test suite validates that:
 * 1. The Inventory class now uses PreparedStatement instead of direct string concatenation
 * 2. User input is properly sanitized through parameterized queries
 * 3. SQL injection attack vectors are neutralized
 * 4. Normal functionality remains intact
 */
@RunWith(MockitoJUnitRunner.class)
public class InventoryTest {

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private ActionEvent mockActionEvent;

    private Inventory inventory;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        inventory = new Inventory();

        // Mock the connection and prepared statement behavior
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Set the connection on the inventory object
        inventory.con = mockConnection;
    }

    @After
    public void tearDown() {
        inventory = null;
    }

    /**
     * Test 1: Verify that PreparedStatement is used for database operations
     * This ensures the vulnerability fix is in place
     */
    @Test
    public void testUsesParameterizedQuery() throws Exception {
        // Arrange
        setInventoryFields("STYLE001", "01/01/2024", "VENDOR001", "Diamond", "2.5", "10", "18", "50.5", "Test item");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify PreparedStatement was created with parameterized query
        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());

        String capturedQuery = queryCaptor.getValue();

        // The query should contain placeholders (?) instead of concatenated values
        assertTrue("Query should use parameterized placeholders", capturedQuery.contains("?"));
        assertFalse("Query should not contain concatenated style_id value", capturedQuery.contains("STYLE001"));
        assertFalse("Query should not contain concatenated vendor_id value", capturedQuery.contains("VENDOR001"));
    }

    /**
     * Test 2: Verify SQL injection attempt with malicious style_id is neutralized
     * Attack vector: Attempting to inject SQL through style_id field
     */
    @Test
    public void testSqlInjectionAttempt_StyleId() throws Exception {
        // Arrange - Malicious input attempting SQL injection
        String maliciousInput = "' OR '1'='1"; // Classic SQL injection attempt
        setInventoryFields(maliciousInput, "01/01/2024", "VENDOR001", "Diamond", "2.5", "10", "18", "50.5", "Test item");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify the malicious input is passed as a parameter, not concatenated
        verify(mockPreparedStatement).setString(eq(1), eq(maliciousInput));
        verify(mockPreparedStatement).executeUpdate();

        // Verify PreparedStatement was used (not Statement)
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test 3: Verify SQL injection attempt with DROP TABLE command is neutralized
     * Attack vector: Attempting to drop the table through details field
     */
    @Test
    public void testSqlInjectionAttempt_DropTable() throws Exception {
        // Arrange - Malicious input attempting to drop table
        String maliciousDetails = "'); DROP TABLE Inventory; --";
        setInventoryFields("STYLE001", "01/01/2024", "VENDOR001", "Diamond", "2.5", "10", "18", "50.5", maliciousDetails);

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify the malicious input is safely passed as a string parameter
        verify(mockPreparedStatement).setString(eq(9), eq(maliciousDetails));
        verify(mockPreparedStatement).executeUpdate();

        // The malicious SQL should be treated as a literal string, not executed
        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());
        assertFalse("Query should not contain DROP TABLE command",
                    queryCaptor.getValue().toUpperCase().contains("DROP TABLE"));
    }

    /**
     * Test 4: Verify SQL injection with UNION SELECT is neutralized
     * Attack vector: Attempting data exfiltration through UNION SELECT
     */
    @Test
    public void testSqlInjectionAttempt_UnionSelect() throws Exception {
        // Arrange - Malicious input attempting UNION SELECT attack
        String maliciousVendorId = "VENDOR001' UNION SELECT * FROM users WHERE '1'='1";
        setInventoryFields("STYLE001", "01/01/2024", maliciousVendorId, "Diamond", "2.5", "10", "18", "50.5", "Test item");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify the malicious input is passed as a parameter
        verify(mockPreparedStatement).setString(eq(2), eq(maliciousVendorId));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 5: Verify SQL injection with comment injection is neutralized
     * Attack vector: Using SQL comments to bypass validation
     */
    @Test
    public void testSqlInjectionAttempt_CommentInjection() throws Exception {
        // Arrange - Malicious input using SQL comment syntax
        String maliciousInput = "VENDOR001'; -- ";
        setInventoryFields("STYLE001", "01/01/2024", maliciousInput, "Diamond", "2.5", "10", "18", "50.5", "Test item");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify the comment syntax is treated as literal string
        verify(mockPreparedStatement).setString(eq(2), eq(maliciousInput));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 6: Verify normal legitimate data insertion works correctly
     * This ensures the fix doesn't break normal functionality
     */
    @Test
    public void testLegitimateDataInsertion() throws Exception {
        // Arrange - Normal legitimate data
        setInventoryFields("STYLE123", "12/25/2024", "VENDOR456", "Ruby", "3.0", "15", "22", "75.8", "Beautiful ruby necklace");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify all parameters are set correctly
        verify(mockPreparedStatement).setString(1, "STYLE123");
        verify(mockPreparedStatement).setString(2, "VENDOR456");
        verify(mockPreparedStatement).setString(3, "12/25/2024");
        verify(mockPreparedStatement).setString(4, "22");
        verify(mockPreparedStatement).setString(5, "75.8");
        verify(mockPreparedStatement).setString(6, "Ruby");
        verify(mockPreparedStatement).setString(7, "3.0");
        verify(mockPreparedStatement).setString(8, "15");
        verify(mockPreparedStatement).setString(9, "Beautiful ruby necklace");
        verify(mockPreparedStatement).executeUpdate();
        verify(mockPreparedStatement).close();
    }

    /**
     * Test 7: Verify special characters in legitimate data are handled correctly
     * Tests that apostrophes and quotes in legitimate data don't cause issues
     */
    @Test
    public void testLegitimateDataWithSpecialCharacters() throws Exception {
        // Arrange - Legitimate data containing apostrophes and special characters
        String details = "Customer's special request: 'custom engraving'";
        setInventoryFields("STYLE999", "06/15/2024", "VENDOR789", "Emerald", "1.5", "8", "18", "45.2", details);

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify special characters are handled safely
        verify(mockPreparedStatement).setString(eq(9), eq(details));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 8: Verify batch SQL injection attempts with multiple attack vectors
     * Attack vector: Multiple SQL injection techniques in single input
     */
    @Test
    public void testComplexSqlInjectionAttempt() throws Exception {
        // Arrange - Complex multi-vector SQL injection attempt
        String complexAttack = "'; DELETE FROM Inventory WHERE '1'='1' OR 1=1; UPDATE Inventory SET Gold='0'; --";
        setInventoryFields("STYLE001", "01/01/2024", "VENDOR001", "Diamond", "2.5", "10", complexAttack, "50.5", "Test");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify the entire attack string is treated as a single parameter value
        verify(mockPreparedStatement).setString(eq(4), eq(complexAttack));
        verify(mockPreparedStatement).executeUpdate();

        // Verify no Statement object was created (only PreparedStatement should be used)
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test 9: Verify PreparedStatement is properly closed after execution
     * This ensures proper resource management
     */
    @Test
    public void testPreparedStatementIsClosed() throws Exception {
        // Arrange
        setInventoryFields("STYLE001", "01/01/2024", "VENDOR001", "Diamond", "2.5", "10", "18", "50.5", "Test item");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify PreparedStatement is closed
        verify(mockPreparedStatement).close();
    }

    /**
     * Test 10: Verify empty string inputs are handled safely
     * Edge case: All fields empty
     */
    @Test
    public void testEmptyStringInputs() throws Exception {
        // Arrange - Empty string inputs
        setInventoryFields("", "", "", "", "", "", "", "", "");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify empty strings are passed as parameters
        for (int i = 1; i <= 9; i++) {
            verify(mockPreparedStatement).setString(eq(i), eq(""));
        }
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 11: Verify null-like string inputs don't cause SQL injection
     * Attack vector: Using NULL keyword in input
     */
    @Test
    public void testNullStringInjectionAttempt() throws Exception {
        // Arrange - Attempting to inject NULL keyword
        String nullInjection = "NULL'; DROP TABLE Inventory; --";
        setInventoryFields("STYLE001", "01/01/2024", nullInjection, "Diamond", "2.5", "10", "18", "50.5", "Test");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify NULL keyword is treated as literal string
        verify(mockPreparedStatement).setString(eq(2), eq(nullInjection));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test 12: Verify hexadecimal encoding injection attempt is neutralized
     * Attack vector: Using hex-encoded SQL injection
     */
    @Test
    public void testHexEncodedInjectionAttempt() throws Exception {
        // Arrange - Hex-encoded injection attempt
        String hexAttack = "0x27204F52202731273D2731";
        setInventoryFields(hexAttack, "01/01/2024", "VENDOR001", "Diamond", "2.5", "10", "18", "50.5", "Test");

        // Act
        inventory.actionPerformed(mockActionEvent);

        // Assert - Verify hex string is treated as literal parameter
        verify(mockPreparedStatement).setString(eq(1), eq(hexAttack));
        verify(mockPreparedStatement).executeUpdate();
    }

    // Helper method to set inventory fields via reflection or direct access
    private void setInventoryFields(String styleId, String inDate, String vendorId,
                                   String stoneType, String stoneWt, String stoneNumber,
                                   String goldCr, String goldWt, String details) {
        try {
            // Initialize text fields if not already initialized
            if (inventory.style_id == null) inventory.style_id = new JTextField();
            if (inventory.in_date == null) inventory.in_date = new JTextField();
            if (inventory.Vendor_id == null) inventory.Vendor_id = new JTextField();
            if (inventory.stone_type == null) inventory.stone_type = new JTextField();
            if (inventory.stone_wt == null) inventory.stone_wt = new JTextField();
            if (inventory.stone_number == null) inventory.stone_number = new JTextField();
            if (inventory.gold_cr == null) inventory.gold_cr = new JTextField();
            if (inventory.gold_wt == null) inventory.gold_wt = new JTextField();
            if (inventory.details == null) inventory.details = new JTextField();

            // Set the values
            inventory.style_id.setText(styleId);
            inventory.in_date.setText(inDate);
            inventory.Vendor_id.setText(vendorId);
            inventory.stone_type.setText(stoneType);
            inventory.stone_wt.setText(stoneWt);
            inventory.stone_number.setText(stoneNumber);
            inventory.gold_cr.setText(goldCr);
            inventory.gold_wt.setText(goldWt);
            inventory.details.setText(details);
        } catch (Exception e) {
            fail("Failed to set inventory fields: " + e.getMessage());
        }
    }
}
