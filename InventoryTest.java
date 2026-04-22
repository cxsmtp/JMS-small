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
 * Comprehensive test suite for Inventory class SQL injection vulnerability remediation.
 *
 * This test suite validates that:
 * 1. PreparedStatement is used instead of Statement for SQL queries
 * 2. User input is properly parameterized and not concatenated into SQL queries
 * 3. SQL injection attacks are prevented
 * 4. Normal functionality continues to work correctly
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
        inventory = new Inventory();

        // Mock the database connection and prepared statement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);

        // Set the connection on the inventory object
        inventory.con = mockConnection;
    }

    /**
     * Test that PreparedStatement is used with parameterized query.
     * This is the primary defense against SQL injection.
     */
    @Test
    public void testPreparedStatementIsUsed() throws Exception {
        // Set up test data in the text fields
        inventory.style_id = new JTextField("STYLE001");
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test details");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify that prepareStatement was called with a parameterized query (containing ?)
        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());

        String capturedQuery = queryCaptor.getValue();

        // Verify the query uses parameterized placeholders
        assertTrue("Query should use PreparedStatement with ? placeholders",
                   capturedQuery.contains("?"));

        // Verify the query does NOT contain direct value concatenation
        assertFalse("Query should not contain concatenated values",
                    capturedQuery.contains("STYLE001"));
        assertFalse("Query should not contain concatenated values",
                    capturedQuery.contains("VENDOR123"));
    }

    /**
     * Test that all 9 parameters are properly set on the PreparedStatement.
     * This ensures all user inputs are parameterized.
     */
    @Test
    public void testAllParametersAreSet() throws Exception {
        // Set up test data
        String styleId = "STYLE002";
        String vendorId = "VENDOR456";
        String inDate = "02/15/2024";
        String goldCr = "22";
        String goldWt = "15.3";
        String stoneType = "Ruby";
        String stoneWt = "1.8";
        String stoneNumber = "3";
        String details = "High quality stones";

        inventory.style_id = new JTextField(styleId);
        inventory.in_date = new JTextField(inDate);
        inventory.Vendor_id = new JTextField(vendorId);
        inventory.stone_type = new JTextField(stoneType);
        inventory.stone_wt = new JTextField(stoneWt);
        inventory.stone_number = new JTextField(stoneNumber);
        inventory.gold_cr = new JTextField(goldCr);
        inventory.gold_wt = new JTextField(goldWt);
        inventory.details = new JTextField(details);

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify all 9 parameters are set correctly
        verify(mockPreparedStatement).setString(1, styleId);
        verify(mockPreparedStatement).setString(2, vendorId);
        verify(mockPreparedStatement).setString(3, inDate);
        verify(mockPreparedStatement).setString(4, goldCr);
        verify(mockPreparedStatement).setString(5, goldWt);
        verify(mockPreparedStatement).setString(6, stoneType);
        verify(mockPreparedStatement).setString(7, stoneWt);
        verify(mockPreparedStatement).setString(8, stoneNumber);
        verify(mockPreparedStatement).setString(9, details);

        // Verify executeUpdate is called
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempt in style_id field is neutralized.
     * Common attack: SQL injection via closing quote and adding malicious SQL.
     */
    @Test
    public void testSqlInjectionInStyleIdIsNeutralized() throws Exception {
        // Attempt SQL injection in style_id
        String maliciousInput = "' OR '1'='1";

        inventory.style_id = new JTextField(maliciousInput);
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify the malicious input is treated as a literal string parameter
        verify(mockPreparedStatement).setString(1, maliciousInput);

        // Verify no exception is thrown and the method completes successfully
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection with DROP TABLE command is neutralized.
     */
    @Test
    public void testSqlInjectionDropTableIsNeutralized() throws Exception {
        // Attempt SQL injection to drop table
        String maliciousInput = "'; DROP TABLE Inventory; --";

        inventory.style_id = new JTextField(maliciousInput);
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify the entire malicious string is passed as a parameter, not executed as SQL
        verify(mockPreparedStatement).setString(1, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection with UNION SELECT attack is neutralized.
     */
    @Test
    public void testSqlInjectionUnionSelectIsNeutralized() throws Exception {
        // Attempt UNION SELECT injection
        String maliciousInput = "' UNION SELECT * FROM Users WHERE '1'='1";

        inventory.style_id = new JTextField("STYLE001");
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField(maliciousInput);
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify the malicious input is safely parameterized
        verify(mockPreparedStatement).setString(2, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test SQL injection in details field (last parameter) is neutralized.
     */
    @Test
    public void testSqlInjectionInDetailsFieldIsNeutralized() throws Exception {
        // Attempt SQL injection in details field
        String maliciousDetails = "Test'; UPDATE Inventory SET Gold_wt='999' WHERE '1'='1";

        inventory.style_id = new JTextField("STYLE001");
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField(maliciousDetails);

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify the malicious input in details is safely parameterized
        verify(mockPreparedStatement).setString(9, maliciousDetails);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that multiple SQL injection attempts across different fields are all neutralized.
     */
    @Test
    public void testMultipleSqlInjectionAttemptsAreNeutralized() throws Exception {
        // Multiple injection attempts in different fields
        String injection1 = "' OR '1'='1";
        String injection2 = "'; DELETE FROM Inventory; --";
        String injection3 = "' AND 1=1 --";

        inventory.style_id = new JTextField(injection1);
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField(injection2);
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField(injection3);
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify all malicious inputs are safely parameterized
        verify(mockPreparedStatement).setString(1, injection1);
        verify(mockPreparedStatement).setString(2, injection2);
        verify(mockPreparedStatement).setString(8, injection3);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that special characters in legitimate data are handled correctly.
     */
    @Test
    public void testSpecialCharactersInLegitimateDataAreHandled() throws Exception {
        // Legitimate data with special characters that could be problematic
        String detailsWithQuotes = "Details: John's special order with \"quotes\"";
        String styleWithApostrophe = "STYLE'S-001";

        inventory.style_id = new JTextField(styleWithApostrophe);
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField(detailsWithQuotes);

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify special characters are handled as literal strings
        verify(mockPreparedStatement).setString(1, styleWithApostrophe);
        verify(mockPreparedStatement).setString(9, detailsWithQuotes);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that empty strings are handled correctly.
     */
    @Test
    public void testEmptyStringsAreHandledCorrectly() throws Exception {
        inventory.style_id = new JTextField("");
        inventory.in_date = new JTextField("");
        inventory.Vendor_id = new JTextField("");
        inventory.stone_type = new JTextField("");
        inventory.stone_wt = new JTextField("");
        inventory.stone_number = new JTextField("");
        inventory.gold_cr = new JTextField("");
        inventory.gold_wt = new JTextField("");
        inventory.details = new JTextField("");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify all empty strings are passed as parameters
        for (int i = 1; i <= 9; i++) {
            verify(mockPreparedStatement).setString(eq(i), eq(""));
        }
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that numeric fields with SQL injection attempts are neutralized.
     */
    @Test
    public void testSqlInjectionInNumericFieldsIsNeutralized() throws Exception {
        // Attempt SQL injection in numeric fields
        String maliciousWeight = "10.5' OR '1'='1";
        String maliciousCount = "5'; DROP TABLE Inventory; --";

        inventory.style_id = new JTextField("STYLE001");
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField(maliciousWeight);
        inventory.stone_number = new JTextField(maliciousCount);
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify malicious numeric inputs are treated as literal strings
        verify(mockPreparedStatement).setString(7, maliciousWeight);
        verify(mockPreparedStatement).setString(8, maliciousCount);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test regression: ensure the correct SQL query structure is maintained.
     */
    @Test
    public void testCorrectSqlQueryStructure() throws Exception {
        inventory.style_id = new JTextField("STYLE001");
        inventory.in_date = new JTextField("01/01/2024");
        inventory.Vendor_id = new JTextField("VENDOR123");
        inventory.stone_type = new JTextField("Diamond");
        inventory.stone_wt = new JTextField("2.5");
        inventory.stone_number = new JTextField("5");
        inventory.gold_cr = new JTextField("18");
        inventory.gold_wt = new JTextField("10.5");
        inventory.details = new JTextField("Test details");

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Capture the SQL query
        ArgumentCaptor<String> queryCaptor = ArgumentCaptor.forClass(String.class);
        verify(mockConnection).prepareStatement(queryCaptor.capture());

        String query = queryCaptor.getValue();

        // Verify the query structure
        assertTrue("Query should be an INSERT statement",
                   query.trim().toUpperCase().startsWith("INSERT INTO INVENTORY"));
        assertTrue("Query should contain all column names",
                   query.contains("Style_ID") &&
                   query.contains("Vendor_ID") &&
                   query.contains("In_Date") &&
                   query.contains("Gold") &&
                   query.contains("Gold_wt") &&
                   query.contains("Stone_Type") &&
                   query.contains("Stone_Weight") &&
                   query.contains("Stone_numbers") &&
                   query.contains("Details"));

        // Count the number of parameter placeholders (should be 9)
        int paramCount = query.length() - query.replace("?", "").length();
        assertEquals("Query should have exactly 9 parameter placeholders", 9, paramCount);
    }

    @After
    public void tearDown() {
        inventory = null;
    }
}
