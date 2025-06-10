using System.ComponentModel.DataAnnotations.Schema;

namespace LibraryBackend.Models
{
    public class PurchaseRequest
    {
        [Column("id")]
        public int Id { get; set; }

        [ForeignKey("Book")]
        [Column("book_id")]
        public int BookId { get; set; }

        [Column("email")]
        public string Email { get; set; }

        [Column("date")]
        public DateTime Date { get; set; } = DateTime.UtcNow;
    }
}
