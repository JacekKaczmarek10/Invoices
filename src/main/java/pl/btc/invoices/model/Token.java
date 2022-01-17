package pl.btc.invoices.model;

public class Token {
    private long slotId;
    private String label;

    public Token(long slotId, String label) {
        this.slotId = slotId;
        this.label = label;
    }

    @Override
    public String toString() {
        return slotId + ": " + label;
    }
}