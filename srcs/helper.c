#include "packer.h"

void append(void *bin, void *toAppend, size_t size, size_t *offset) {
    memcpy(bin + *offset, toAppend, size);
    *offset += size;
}

void updateOffsets(t_header *header, size_t offset, size_t toAdd, size_t isSection) {
    size_t      i;
    size_t      size;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    if (header->header->e_entry >= offset)
      header->header->e_entry += toAdd;
    if (header->header->e_phoff >= offset)
      header->header->e_phoff += toAdd;
    if (header->header->e_shoff >= offset)
      header->header->e_shoff += toAdd;
    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset >= offset)
            section->sh_offset += toAdd;
        // TODO Better way to handle this
        if (section->sh_link != SHN_UNDEF && isSection && section->sh_link >= header->header->e_shnum - 3)
            section->sh_link += 1;
        if (section->sh_type == SHT_REL) {
            Elf64_Rel *rel;
            size = 0;
            while (size < section->sh_size) {
              rel = ((void *)header->header) + section->sh_offset + (sizeof(Elf64_Rel) * (size / sizeof(Elf64_Rel)));
              if (rel->r_offset >= offset)
                rel->r_offset += toAdd;
              size += sizeof(Elf64_Rel);
            }
        } else if (section->sh_type == SHT_RELA) {
            Elf64_Rela  *rela;
            size = 0;
            while (size < section->sh_size) {
              rela = ((void *)header->header) + section->sh_offset + (sizeof(Elf64_Rela) * (size / sizeof(Elf64_Rela)));
              if (rela->r_offset > offset) {
                // TODO Remove this
                if (!(rela->r_offset == 0x4fe0 && toAdd == 8)) {
                  rela->r_offset += toAdd;
                }
              }
              size += sizeof(Elf64_Rela);
            }
        } else if (section->sh_type == SHT_DYNAMIC) {
            Elf64_Dyn *dyn;
            size = 0;
            while (size < section->sh_size) {
              dyn = ((void *)header->header) + section->sh_offset + (sizeof(Elf64_Dyn) * (size / sizeof(Elf64_Dyn)));
              if (dyn->d_un.d_ptr >= offset)
                dyn->d_un.d_ptr += toAdd;
              size += sizeof(Elf64_Dyn);
            }
            /* Elf64_Move  *move; */
            /* move = ((void *)header->header) + dyn->d_un.d_ptr; */
            /* if (move->m_poffset >= offset) */
            /*   move->m_poffset += toAdd; */
        } else if (section->sh_type == SHT_GNU_verdef) {
            Elf64_Verdef  *verdef;
            verdef = ((void *)header->header) + section->sh_offset;
            if (section->sh_offset < offset && verdef->vd_aux >= offset)
              verdef->vd_aux += toAdd;
            if (section->sh_offset < offset && verdef->vd_next >= offset)
              verdef->vd_aux += toAdd;
        } else if (section->sh_type == SHT_SYMTAB) {
          Elf64_Xword size;
          Elf64_Sym   *symbol;
          size = 0;
          while (size < section->sh_size) {
            symbol = ((void *)header->header) + section->sh_offset + size;
            /* dprintf(2, "Symbol: %s\n", ((void *)header->header) + strtable->sh_offset + symbol->st_name); */
            if (symbol->st_value >= offset) {
              symbol->st_value += toAdd;
            }
            size += sizeof(Elf64_Sym);
          }
        }
        i += 1;
    }
    i = 0;
    while (i < header->header->e_phnum) {
        program = ((void *)header->header) + header->header->e_phoff + i * sizeof(Elf64_Phdr);
        // TODO Handle memsz and filesz correctly
        if (offset >= program->p_offset && offset < program->p_offset + program->p_filesz) {
            program->p_memsz += toAdd;
            program->p_filesz += toAdd;
        }
        if (program->p_offset >= offset)
            program->p_offset += toAdd;
        i += 1;
    }
}

void updateOffsets2(t_header *header, size_t offset, size_t toAdd, size_t isSection) {
    size_t      i;
    Elf64_Shdr  *section;
    Elf64_Phdr  *program;

    /* dprintf(2, "Updating offsets of %zu\n", toAdd); */
    dprintf(2, "Updating offsets\n");
    if (header->header->e_entry >= offset)
      header->header->e_entry += toAdd;
    if (header->header->e_phoff >= offset)
      header->header->e_phoff += toAdd;
    if (header->header->e_shoff >= offset)
      header->header->e_shoff += toAdd;
    i = 0;
    while (i < header->header->e_shnum) {
        section = (void *)(header->header) + header->header->e_shoff + i * sizeof(Elf64_Shdr);
        if (section->sh_offset >= offset)
            section->sh_offset += toAdd;
        // TODO Better way to handle this
        if (section->sh_link != SHN_UNDEF && isSection && section->sh_link >= header->header->e_shnum - 3)
            section->sh_link += 1;
        if (section->sh_type == SHT_REL) {
            Elf64_Rel *rel;
            rel = ((void *)header->header) + section->sh_offset;
            if (rel->r_offset >= offset)
              rel->r_offset += toAdd;
        } else if (section->sh_type == SHT_RELA) {
            Elf64_Rela  *rela;
            rela = ((void *)header->header) + section->sh_offset;
            if (rela->r_offset >= offset)
              rela->r_offset += toAdd;
        } else if (section->sh_type == SHT_DYNAMIC) {
            Elf64_Dyn *dyn;
            dyn = ((void *)header->header) + section->sh_offset;
            if (dyn->d_un.d_ptr >= offset) {
              dyn->d_un.d_ptr += toAdd;
            }
            /* Elf64_Move  *move; */
            /* move = ((void *)header->header) + dyn->d_un.d_ptr; */
            /* if (move->m_poffset >= offset) */
            /*   move->m_poffset += toAdd; */
        } else if (section->sh_type == SHT_GNU_verdef) {
            Elf64_Verdef  *verdef;
            verdef = ((void *)header->header) + section->sh_offset;
            if (section->sh_offset < offset && verdef->vd_aux >= offset)
              verdef->vd_aux += toAdd;
            if (section->sh_offset < offset && verdef->vd_next >= offset)
              verdef->vd_aux += toAdd;
        } else if (section->sh_type == SHT_SYMTAB) {
          Elf64_Xword size;
          Elf64_Sym   *symbol;
          size = 0;
          while (size < section->sh_size) {
            symbol = ((void *)header->header) + section->sh_offset + size;
            if (symbol->st_value >= offset) {
              symbol->st_value += toAdd;
            }
            size += sizeof(Elf64_Sym);
          }
        }
        i += 1;
    }
    i = 0;
    while (i < header->header->e_phnum) {
        program = ((void *)header->header) + header->header->e_phoff + i * sizeof(Elf64_Phdr);
        if (program->p_offset >= offset)
            program->p_offset += toAdd;
        i += 1;
    }
}
