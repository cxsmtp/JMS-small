import org.junit.Before;
import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.MockitoJUnitRunner;

import java.sql.*;
import javax.swing.*;
import java.awt.event.ActionEvent;

import static org.mockito.Mockito.*;
import static org.junit.Assert.*;

/**
 * Test suite for Inventory class to verify SQL injection vulnerability remediation.
 * Tests ensure that PreparedStatement with parameterized queries is used correctly
 * to prevent SQL injection attacks.
 */
@RunWith(MockitoJUnitRunner.class)
public class InventoryTest {

    private Inventory inventory;

    @Mock
    private Connection mockConnection;

    @Mock
    private PreparedStatement mockPreparedStatement;

    @Mock
    private ActionEvent mockActionEvent;

    @Before
    public void setUp() throws Exception {
        MockitoAnnotations.initMocks(this);
        inventory = new Inventory();

        // Mock the database connection and prepared statement
        when(mockConnection.prepareStatement(anyString())).thenReturn(mockPreparedStatement);
        when(mockPreparedStatement.executeUpdate()).thenReturn(1);
    }

    @After
    public void tearDown() {
        inventory = null;
    }

    /**
     * Test that PreparedStatement is used instead of plain Statement.
     * This is the core fix for SQL injection vulnerability.
     */
    @Test
    public void testPreparedStatementIsUsed() throws Exception {
        // Set up test data in the text fields
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test inventory item");

        // Mock the connection
        inventory.con = mockConnection;

        // Trigger the action
        inventory.actionPerformed(mockActionEvent);

        // Verify that prepareStatement was called with a parameterized query
        verify(mockConnection).prepareStatement(contains("VALUES (?,?,?,?,?,?,?,?,?)"));

        // Verify that the string concatenation query is NOT used
        verify(mockConnection, never()).createStatement();
    }

    /**
     * Test that SQL injection attempt in style_id is safely handled.
     * Malicious input should be treated as a literal string, not executed as SQL.
     */
    @Test
    public void testSqlInjectionInStyleIdIsBlocked() throws Exception {
        // Attempt SQL injection in style_id field
        String maliciousInput = "'); DROP TABLE Inventory; --";

        inventory.style_id.setText(maliciousInput);
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Normal details");

        inventory.con = mockConnection;

        // Execute the action
        inventory.actionPerformed(mockActionEvent);

        // Verify PreparedStatement is used
        verify(mockConnection).prepareStatement(anyString());

        // Verify that the malicious string is passed as a parameter (position 1)
        // and will be escaped by PreparedStatement
        verify(mockPreparedStatement).setString(1, maliciousInput);

        // Verify the query executes safely
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempt in vendor_id is safely handled.
     */
    @Test
    public void testSqlInjectionInVendorIdIsBlocked() throws Exception {
        String maliciousInput = "' OR '1'='1";

        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText(maliciousInput);
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Normal details");

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify the malicious string is passed as parameter 2
        verify(mockPreparedStatement).setString(2, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL injection attempt in details field is safely handled.
     * The details field is particularly vulnerable as it accepts longer text.
     */
    @Test
    public void testSqlInjectionInDetailsIsBlocked() throws Exception {
        String maliciousInput = "Normal details'; UPDATE Inventory SET Gold_wt='0' WHERE '1'='1";

        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(maliciousInput);

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify the malicious string is passed as parameter 9 (details is last)
        verify(mockPreparedStatement).setString(9, maliciousInput);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that all parameters are correctly set in PreparedStatement.
     * Ensures proper parameter binding order.
     */
    @Test
    public void testAllParametersAreCorrectlySet() throws Exception {
        String styleId = "STYLE123";
        String vendorId = "VENDOR456";
        String inDate = "22/04/2026";
        String goldCarat = "22";
        String goldWeight = "15.5";
        String stoneType = "Ruby";
        String stoneWeight = "3.2";
        String stoneNumber = "8";
        String details = "Premium quality";

        inventory.style_id.setText(styleId);
        inventory.Vendor_id.setText(vendorId);
        inventory.in_date.setText(inDate);
        inventory.gold_cr.setText(goldCarat);
        inventory.gold_wt.setText(goldWeight);
        inventory.stone_type.setText(stoneType);
        inventory.stone_wt.setText(stoneWeight);
        inventory.stone_number.setText(stoneNumber);
        inventory.details.setText(details);

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify all 9 parameters are set in correct order
        verify(mockPreparedStatement).setString(1, styleId);
        verify(mockPreparedStatement).setString(2, vendorId);
        verify(mockPreparedStatement).setString(3, inDate);
        verify(mockPreparedStatement).setString(4, goldCarat);
        verify(mockPreparedStatement).setString(5, goldWeight);
        verify(mockPreparedStatement).setString(6, stoneType);
        verify(mockPreparedStatement).setString(7, stoneWeight);
        verify(mockPreparedStatement).setString(8, stoneNumber);
        verify(mockPreparedStatement).setString(9, details);

        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that special characters in input are safely handled.
     * Ensures single quotes, double quotes, and backslashes don't break the query.
     */
    @Test
    public void testSpecialCharactersAreHandledSafely() throws Exception {
        String inputWithSpecialChars = "O'Reilly's \"Special\" Item\\Path";

        inventory.style_id.setText(inputWithSpecialChars);
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText(inputWithSpecialChars);
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText(inputWithSpecialChars);

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify special characters are passed as literal strings
        verify(mockPreparedStatement).setString(1, inputWithSpecialChars);
        verify(mockPreparedStatement).setString(6, inputWithSpecialChars);
        verify(mockPreparedStatement).setString(9, inputWithSpecialChars);
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that PreparedStatement is properly closed after execution.
     * Ensures no resource leaks.
     */
    @Test
    public void testPreparedStatementIsClosed() throws Exception {
        inventory.style_id.setText("STYLE001");
        inventory.Vendor_id.setText("VENDOR001");
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("Diamond");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("Test item");

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify PreparedStatement is closed after use
        verify(mockPreparedStatement).close();
    }

    /**
     * Test that empty/null inputs are handled without SQL injection risk.
     */
    @Test
    public void testEmptyInputsAreHandledSafely() throws Exception {
        inventory.style_id.setText("");
        inventory.Vendor_id.setText("");
        inventory.in_date.setText("");
        inventory.gold_cr.setText("");
        inventory.gold_wt.setText("");
        inventory.stone_type.setText("");
        inventory.stone_wt.setText("");
        inventory.stone_number.setText("");
        inventory.details.setText("");

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify empty strings are safely passed as parameters
        verify(mockPreparedStatement, times(9)).setString(anyInt(), eq(""));
        verify(mockPreparedStatement).executeUpdate();
    }

    /**
     * Test that SQL keywords in input are treated as literal strings.
     */
    @Test
    public void testSqlKeywordsAreTreatedAsLiterals() throws Exception {
        String sqlKeywords = "SELECT * FROM Users WHERE admin=true";

        inventory.style_id.setText(sqlKeywords);
        inventory.Vendor_id.setText("UNION SELECT password FROM users");
        inventory.in_date.setText("22/04/2026");
        inventory.gold_cr.setText("24");
        inventory.gold_wt.setText("10.5");
        inventory.stone_type.setText("DELETE FROM Inventory");
        inventory.stone_wt.setText("2.5");
        inventory.stone_number.setText("5");
        inventory.details.setText("DROP DATABASE JMS");

        inventory.con = mockConnection;

        inventory.actionPerformed(mockActionEvent);

        // Verify SQL keywords are passed as literal parameter values
        verify(mockPreparedStatement).setString(1, sqlKeywords);
        verify(mockPreparedStatement).setString(2, "UNION SELECT password FROM users");
        verify(mockPreparedStatement).setString(6, "DELETE FROM Inventory");
        verify(mockPreparedStatement).setString(9, "DROP DATABASE JMS");
        verify(mockPreparedStatement).executeUpdate();
    }
}
