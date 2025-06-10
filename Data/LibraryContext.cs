namespace LibraryBackend.Data
{
    using Models;
    using Microsoft.EntityFrameworkCore;
    using System.ComponentModel.DataAnnotations.Schema;

    public class LibraryContext : DbContext
    {
        public DbSet<Book> Books { get; set; }
        public DbSet<PurchaseRequest> PurchaseRequests { get; set; }
        public DbSet<User> Users { get; set; }

        protected override void OnConfiguring(DbContextOptionsBuilder options)
            => options.UseNpgsql("Host=localhost;Database=online_library;Username=wincero;Password=123456");

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<Book>(entity =>
            {
                entity.ToTable("books"); 
                entity.HasKey(b => b.Id);
                entity.Property(b => b.SimilarBooks)
                    .HasColumnType("integer[]");
            });

            modelBuilder.Entity<PurchaseRequest>(entity =>
            {
                entity.ToTable("purchase_requests");
                entity.HasKey(pr => pr.Id);

                entity.HasOne<Book>()
                    .WithMany()
                    .HasForeignKey(pr => pr.BookId)
                    .OnDelete(DeleteBehavior.Cascade);
            });

            modelBuilder.Entity<User>(entity =>
            {
                entity.ToTable("users");
                entity.HasKey(u => u.Id);
                entity.HasIndex(u => u.Login).IsUnique();
            });
        }
    }
}
