namespace LibraryBackend.Controllers
{
    using LibraryBackend.Data;
    using LibraryBackend.Models;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;

    [ApiController]
    [Route("api/books")]
    public class BooksController : ControllerBase
    {
        private readonly LibraryContext _context;

        public BooksController(LibraryContext context)
        {
            _context = context;
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<Book>>> GetBooks(
        [FromQuery] string? title,
        [FromQuery] string? author,
        [FromQuery] string? category,
        [FromQuery] bool? isFree)
        {
            var query = _context.Books.AsQueryable();

            if (!string.IsNullOrEmpty(title))
                query = query.Where(b => b.Title.ToLower().Contains(title.ToLower()));

            if (!string.IsNullOrEmpty(author))
                query = query.Where(b => b.Author.ToLower().Contains(author.ToLower()));

            if (!string.IsNullOrEmpty(category))
                query = query.Where(b => b.Category.ToLower().Contains(category.ToLower()));

            if (isFree.HasValue)
                query = query.Where(b => b.IsFree == isFree);

            var q = query.ToQueryString();
            Console.WriteLine(q);
            return await query.ToListAsync();
        }

        [HttpGet("{id}")]
        public async Task<ActionResult<Book>> GetBook(int id)
        {
            var book = await _context.Books.FindAsync(id);
            if (book == null)
            {
                return NotFound();
            }
            return book;
        }
    }
}
