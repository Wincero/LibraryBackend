using System.ComponentModel.DataAnnotations.Schema;

namespace LibraryBackend.Models
{
    public class Book
    {
        [Column("id")]
        public int Id { get; set; }

        [Column("title")]
        public string Title { get; set; }

        [Column("author")]
        public string Author { get; set; }

        [Column("category")]
        public string Category { get; set; }

        [Column("is_free")]
        public bool IsFree { get; set; }

        [Column("annotation")]
        public string? Annotation { get; set; } 

        [Column("file_url")]
        public string FileUrl { get; set; }

        [Column("total_pages")]
        public int TotalPages { get; set; }

        [Column("cover_image")]
        public string? CoverImage { get; set; }

        [Column("similar_books")]
        public List<int> SimilarBooks { get; set; } = new();
    }
}
